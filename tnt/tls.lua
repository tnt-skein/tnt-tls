--- Шифрование обычного сокета в Community Edition.
---
--- В Community Edition прикладному коду шифровать нечем: `require('ssl')`
--- там нет, а шифрование iproto доступно только ядру Enterprise Edition.
--- Поэтому всё, что ходит по TCP из Lua — почта по SMTP, IMAP и POP3,
--- запросы к чужим службам, — уходит открытым текстом вместе с паролями
--- учётных записей. Пакет закрывает эту дыру тем, что в Community Edition
--- всё же есть: системной OpenSSL через FFI.
---
--- Два входа, потому что TLS поднимают двумя способами. На портах 465,
--- 993 и 995 шифрование начинается сразу — это `connect`. В STARTTLS
--- разговор начинается открытым текстом, клиент просит перейти на
--- шифрование и поднимает TLS поверх того же сокета — это `wrap`.
---
--- Проверка сертификата включена по умолчанию. Шифрование без проверки
--- защищает от подслушивания, но не от подмены: тот, кто может читать
--- трафик, обычно может и встать посередине, и тогда шифрованный канал
--- идёт к нему. Поэтому `verify = false` — осознанный выбор вызывающего,
--- уместный разве что против сервера с самоподписанным сертификатом
--- в своём же контуре, и ничем, кроме этой строки в опциях, он себя
--- не выдаёт.
---
--- Сертификат, не прошедший проверку, отличается от прочих отказов словом
--- `untrusted` третьим значением: сеть, моргнувшая на полсекунды,
--- поднимется сама, а чужой сертификат останется чужим, и тот, кто
--- повторяет соединение до конца срока, по этому слову отказывает сразу.
---
--- Пользоваться так:
---
---     local tls = require('tnt.tls')
---
---     local link, err = tls.connect({ host = 'smtp.example.org', port = 465 })
---
---     if link == nil then
---         return nil, err
---     end
---
---     link:write('EHLO узел\r\n')
---
---     local answer = link:read({ delimiter = '\r\n' })
---
---     link:close()

local link = require('tnt.tls.link')
local openssl = require('tnt.tls.openssl')
local options = require('tnt.tls.options')
local outcome = require('tnt.tls.outcome')
local external = require('tnt.external')

local Module = {}

--- Род отказа: сертификат другой стороны не принят (`tnt.tls.outcome`).
Module.UNTRUSTED = outcome.UNTRUSTED

--- Внешние средства: слой OpenSSL и сеть.
local source = external.install(Module, {
    backend = function()
        return openssl
    end,

    connect = function(host, port, timeout)
        return require('socket').tcp_connect(host, port, timeout)
    end,
})

---@class TntTlsOptions
---@field host string Имя узла; по нему же проверяется сертификат
---@field port integer|nil Порт; у connect обязателен, у wrap не нужен
---@field timeout number|nil Срок одной операции в секундах, по умолчанию 5
---@field verify boolean|nil Проверять ли сертификат, по умолчанию да
---@field ca_file string|nil Файл доверенных корней вместо системных
---@field ca_path string|nil Каталог доверенных корней вместо системных
---@field sni string|nil Имя для SNI, по умолчанию host
---@field cert_file string|nil Сертификат клиента PEM — серверу, который его спрашивает
---@field key_file string|nil Ключ клиента PEM без пароля; по умолчанию из cert_file

--- Есть ли на этой машине чем шифровать.
---
--- Спрашивать стоит до того, как строить работу на шифровании:
--- «TLS недоступен» в начале — это настройка, а посреди отправки
--- письма — потерянное письмо. Причина возвращается вместе с ответом
--- и перечисляет, где библиотеку искали.
---@return boolean
---@return string|nil err
function Module.available()
    local lib, err = source().backend().library()

    if lib == nil then
        return false, err
    end

    return true
end

--- Соединяется и сразу поднимает TLS.
---
--- Для портов, на которых шифрование начинается с первого байта: 465
--- у SMTP, 993 у IMAP, 995 у POP3.
---@param opts TntTlsOptions Порт обязателен
---@return TntTlsLink|nil
---@return string|nil err
---@return string|nil kind `UNTRUSTED`, если не принят сертификат сервера
function Module.connect(opts)
    local settings, wrong = options.normalize(opts, true)

    if settings == nil then
        return nil, wrong
    end

    -- Через pcall: tcp_connect на негодном имени узла бывает, что
    -- не возвращает причину, а поднимает ошибку, и уронить ею отправителя
    -- письма было бы несоразмерно.
    local ok, socket, reason = pcall(source().connect, settings.host, settings.port, settings.timeout)

    -- Причина отказа идёт в текст, когда она есть: «Connection refused»
    -- и «имя не разрешилось» чинятся по-разному, а без неё оба выглядели
    -- бы истёкшим сроком, хотя пришли мгновенно.
    if not ok or socket == nil and reason ~= nil then
        return nil,
            ('соединение с %s:%s не открылось: %s'):format(
                settings.host,
                settings.port,
                tostring(ok and reason or socket)
            )
    end

    if socket == nil then
        return nil,
            ('соединение с %s:%s не открылось за %s с'):format(
                settings.host,
                settings.port,
                settings.timeout
            )
    end

    local established, err, kind = link.establish(socket, settings, source().backend())

    if established == nil then
        -- Сокет открыл этот модуль — ему и закрывать: после сорванного
        -- рукопожатия он не годится ни на что, а оставленный открытым
        -- он утёкший дескриптор.
        pcall(socket.close, socket)

        return nil, err, kind
    end

    return established
end

--- Поднимает TLS поверх уже открытого сокета.
---
--- Так работает STARTTLS: разговор начат открытым текстом, сервер
--- согласился перейти на шифрование, и с этого места по тому же сокету
--- идёт TLS. Имя узла обязательно и здесь: сертификат проверяется
--- по нему, а сокет своего имени не помнит — только адрес, по которому
--- сертификат обычно не выписан.
---
--- Сокет при отказе остаётся вызывающего: закрыть чужой сокет за него
--- значит однажды закрыть тот, который ему ещё нужен.
---@param socket table Объект require('socket')
---@param opts TntTlsOptions Порта здесь нет: сокет уже открыт
---@return TntTlsLink|nil
---@return string|nil err
---@return string|nil kind `UNTRUSTED`, если не принят сертификат сервера
function Module.wrap(socket, opts)
    if type(socket) ~= 'table' then
        return nil, 'нет сокета, поверх которого поднимать TLS'
    end

    local settings, wrong = options.normalize(opts, false)

    if settings == nil then
        return nil, wrong
    end

    return link.establish(socket, settings, source().backend())
end

return Module
