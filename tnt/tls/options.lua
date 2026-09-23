--- Разбор опций соединения.
---
--- Опции приходят от прикладного кода, и ошибка в них обязана
--- обнаружиться до того, как открыт сокет: соединение, поднятое
--- с пропущенным `verify`, выглядит точно так же, как проверенное,
--- и разница видна только тому, кто перехватывает трафик.
---
--- Умолчания выбраны в пользу строгости. Проверка сертификата включена,
--- пока её не выключили словом: обратный выбор означал бы, что забывший
--- про `verify` получает шифрование без всякой защиты от подмены —
--- а это ровно то шифрование, которое даёт ложное спокойствие.
---
--- Модуль чистый: ни сокета, ни библиотеки, ни времени.

local Module = {}

--- Сколько ждать чужую машину, если не сказано иное.
---
--- Пять секунд: исправный сервер успевает за них и принять соединение,
--- и договориться о ключах с большим запасом, а молчащий дольше скорее
--- всего не ответит вовсе — и вызывающий узнаёт об этом, пока ещё может
--- что-то сделать.
Module.DEFAULT_TIMEOUT = 5

---@class TntTlsSettings
---@field host string Имя узла: по нему же проверяется сертификат
---@field port number|nil Порт; у STARTTLS сокет уже открыт, и порта нет
---@field timeout number Срок одной операции в секундах
---@field verify boolean Проверять ли сертификат
---@field ca_file string|nil Файл доверенных корней вместо системных
---@field ca_path string|nil Каталог доверенных корней вместо системных
---@field sni string|nil Имя для расширения SNI либо nil, если его не слать
---@field cert_file string|nil Сертификат клиента PEM, с цепочкой до корня
---@field key_file string|nil Ключ клиента PEM без пароля; по умолчанию cert_file

--- Похож ли узел на числовой адрес.
---
--- Отвечает на два вопроса сразу. В расширение SNI по RFC 6066 адрес
--- слать нельзя — сервер вправе оборвать рукопожатие, и некоторые
--- обрывают. А проверка имени для адреса идёт по другому полю
--- сертификата, и знать об этом должен тот, кто читает отказ.
---@param host string
---@return boolean
function Module.looks_like_address(host)
    -- Двоеточие бывает только в IPv6: в доменном имени его не бывает,
    -- а порт сюда не приходит — он отдельной опцией. Ищется образцом без
    -- начала и флага: двоеточие в образце ничего не значит, а у начала `1`
    -- и флага «как есть» мутанты находят то же самое.
    if host:find(':') ~= nil then
        return true
    end

    return host:match('^%d+%.%d+%.%d+%.%d+$') ~= nil
end

--- Необязательные опции, которые уходят в OpenSSL строками: пути
--- к доверенным корням, имя для SNI, сертификат и ключ клиента.
---
--- Тип проверяется здесь, а не на входе в библиотеку: там не строка —
--- это исключение FFI посреди настройки соединения вместо отказа парой,
--- и сокет, открытый `connect`, остался бы незакрытым.
local TEXTS = { 'ca_file', 'ca_path', 'sni', 'cert_file', 'key_file' }

--- Проверяет порт.
---@param value any
---@return number|nil port
---@return string|nil err
local function port_of(value)
    local port = tonumber(value)

    if port == nil or port ~= math.floor(port) or port < 1 or port > 65535 then
        return nil,
            ('порт должен быть числом от 1 до 65535, а не %s'):format(tostring(value))
    end

    return port
end

--- Приводит опции к виду, на котором написан весь остальной пакет.
---@param opts table|nil Что передал вызывающий
---@param needs_port boolean|nil Нужен ли порт: у STARTTLS сокет уже открыт
---@return TntTlsSettings|nil settings
---@return string|nil err
function Module.normalize(opts, needs_port)
    if type(opts) ~= 'table' then
        return nil, 'опции не переданы: нужен хотя бы { host = ... }'
    end

    local host = opts.host

    if type(host) ~= 'string' or host == '' then
        return nil, 'не сказано, с каким узлом соединяться: нет host'
    end

    local port

    if needs_port then
        local chosen, err = port_of(opts.port)

        if chosen == nil then
            return nil, err
        end

        port = chosen
    elseif opts.port ~= nil then
        local chosen, err = port_of(opts.port)

        if chosen == nil then
            return nil, err
        end

        port = chosen
    end

    local timeout = opts.timeout

    if timeout == nil then
        timeout = Module.DEFAULT_TIMEOUT
    else
        timeout = tonumber(timeout)

        -- Нулевой срок — не «ждать вечно», а «не ждать вовсе»: на нём
        -- не проходит ни одно рукопожатие, и отказ будет непонятным.
        if timeout == nil or timeout <= 0 then
            return nil,
                ('срок ожидания должен быть положительным числом, а не %s'):format(
                    tostring(opts.timeout)
                )
        end
    end

    for _, name in ipairs(TEXTS) do
        local value = opts[name]

        if value ~= nil and type(value) ~= 'string' then
            return nil, ('%s должен быть строкой, а не %s'):format(name, type(value))
        end
    end

    -- Ключ без сертификата предъявить нечем: сервер спрашивает сертификат,
    -- а ключ лишь доказывает, что он наш. Молча обойтись без ключа значило
    -- бы соединиться без сертификата и узнать об этом отказом сервера —
    -- после рукопожатия, с текстом, в котором про ключ ни слова.
    if opts.key_file ~= nil and opts.cert_file == nil then
        return nil,
            'key_file без cert_file: ключ предъявляется только вместе с сертификатом'
    end

    -- Проверка выключается только словом `false`. Всякое другое значение,
    -- включая строку «false» из конфигурации, оставляет её включённой:
    -- ошибиться в сторону строгости здесь безопасно, в другую — нет.
    local verify = opts.verify ~= false

    ---@type TntTlsSettings
    local settings = {
        host = host,
        port = port,
        timeout = timeout,
        verify = verify,
        ca_file = opts.ca_file,
        ca_path = opts.ca_path,
        sni = Module.server_name(host, opts.sni),
        cert_file = opts.cert_file,
        -- Ключ без своего файла берётся из файла сертификата: сертификат
        -- и ключ часто лежат одним файлом PEM, и называть его дважды
        -- незачем. Если ключа там нет, отказ скажет это при соединении.
        key_file = opts.key_file or opts.cert_file,
    }

    return settings
end

--- Какое имя слать в SNI.
---
--- По умолчанию то же, с которым соединяемся: виртуальных почтовых
--- серверов на одном адресе столько же, сколько виртуальных сайтов,
--- и без SNI такой сервер отдаёт сертификат не тот.
---
--- Для числового адреса имени нет вовсе: слать адрес запрещено.
---@param host string
---@param given string|nil Имя, заданное вызывающим
---@return string|nil
function Module.server_name(host, given)
    local name = given or host

    if type(name) ~= 'string' or name == '' or Module.looks_like_address(name) then
        return nil
    end

    return name
end

return Module
