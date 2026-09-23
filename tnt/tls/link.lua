--- Защищённое соединение: рукопожатие, чтение, запись, прощание.
---
--- Здесь живёт всё, что делает пакет кооперативным. OpenSSL на
--- неблокирующем сокете отвечает не «ошибка», а «повтори, когда
--- дескриптор будет готов», и разница между хорошим модулем и негодным
--- ровно в том, как он это «когда» пережидает. Крутить цикл нельзя —
--- файбер займёт поток целиком. Переводить сокет в блокирующий режим
--- нельзя тем более: блокирующий SSL_read останавливает не файбер,
--- а весь узел, вместе с репликацией, откликом на iproto и пробами
--- живости. Поэтому ожидание — файберное: `socket:readable`
--- и `socket:writable` снимают файбер с потока и возвращают его, когда
--- ядро говорит о готовности.
---
--- Срок назначается на операцию, а не на соединение целиком: так же
--- устроен и обычный сокет, и построчный протокол, который ждёт ответа
--- на каждую команду, иначе исчерпал бы общий срок на середине разговора.
---
--- Про OpenSSL модуль не знает ничего: слой FFI приходит аргументом
--- и отвечает состояниями. Поэтому все ветки — обрыв, срок, отказ
--- посреди записи — проверяются без сервера и без библиотеки.

local errno = require('errno')

local clock = require('tnt.clock')

local buffer = require('tnt.tls.buffer')
local outcome = require('tnt.tls.outcome')
local external = require('tnt.external')

local Module = {}

--- Сколько ждать чужое прощание при закрытии.
---
--- Секунда, и не больше срока соединения. Дождаться close_notify
--- вежливо, но сервер вправе закрыть сокет сразу же, и ждать его
--- полным сроком значит держать файбер на закрытии дольше, чем
--- на самом разговоре.
local SHUTDOWN_WAIT = 1

--- Сколько раз пытаться попрощаться.
---
--- Два вызова SSL_shutdown — это и есть двустороннее прощание: первый
--- шлёт своё, второй читает чужое. Ожидания готовности между ними
--- добавляют обороты, поэтому предел с запасом; настоящий предел —
--- срок.
local SHUTDOWN_ROUNDS = 4

--- Ответ ядра «читать пока нечего»: в сокете пусто, и конца потока нет.
---
--- `EWOULDBLOCK` отдельно не сверяется: на Linux и macOS это то же число,
--- что и `EAGAIN` (11 и 35).
local AGAIN = errno.EAGAIN

--- Внешние средства: часы.
---
--- Не стенные: перевод стенных часов назад посреди рукопожатия продлил бы
--- его на разницу. Монотонных двое, по правилу `tnt-clock`. Срок операции —
--- миг, и отмечается он настоящими часами в миг вызова: отметка цикла
--- событий стоит с последней уступки вызывающего, и его работа без уступки
--- перед вызовом съела бы часть срока. Остаток же уходит в ожидание
--- готовности сокета, а оно отсчитывает его от отметки цикла, поэтому
--- считается от времени планировщика. OpenSSL между ожиданиями считает
--- не уступая — ключи рукопожатия считаются миллисекундами, — и остаток
--- по настоящим часам вышел бы короче на это время. Перепроверки после
--- ожидания нет: соединение объявило бы «не уложилось в срок», не дождавшись
--- его. С двумя часами ожидание кончается ровно в срок, и отказ называет
--- тот срок, которого ждали.
local source = external.install(Module, {
    monotonic = clock.monotonic,
    scheduler_now = clock.scheduler_now,
})

---@class TntTlsLink
---@field read fun(self: TntTlsLink, opts: table|number, timeout: number|nil): string|nil, string|nil
---@field write fun(self: TntTlsLink, text: string, timeout: number|nil): boolean, string|nil
---@field close fun(self: TntTlsLink)
---@field idle fun(self: TntTlsLink): boolean
---@field peer fun(self: TntTlsLink): { host: string, port: integer|nil, cipher: string|nil, protocol: string|nil }

--- Спрашивает сокет, готов ли дескриптор, и ждёт не дольше остатка.
---@param socket table
---@param wait function socket.readable либо socket.writable
---@param left number Остаток срока, больше нуля
---@return boolean
local function answered(socket, wait, left)
    -- Через pcall: сокет, закрытый другим файбером, отвечает на ожидание
    -- ошибкой, и это не повод ронять того, кто просто читал.
    local ok, answer = pcall(wait, socket, left)

    return ok and answer ~= nil and answer ~= false
end

--- Дожидается готовности дескриптора.
---
--- Отрицательный остаток срока не отдаётся сокету: `readable` понимает
--- его по-своему, и «уже поздно» превратилось бы в «жди сколько
--- угодно». Вышедший срок отвечает «не готов» тем же выражением,
--- а не отдельным `return false`: вызывающий смотрит только на
--- истинность ответа, и пустота вместо `false` там ничем не отличима.
---@param socket table
---@param wait function socket.readable либо socket.writable
---@param deadline number Срок по настоящим часам
---@param scheduler_now fun(): number Время планировщика
---@return boolean
local function ready(socket, wait, deadline, scheduler_now)
    local left = deadline - scheduler_now()

    return left > 0 and answered(socket, wait, left)
end

--- Порт другой стороны.
---
--- У STARTTLS порта в опциях нет: сокет открыл вызывающий. Спросить
--- его у сокета дешевле, чем требовать порт второй раз.
---@param socket table
---@param given number|nil
---@return number|nil
function Module.port_of(socket, given)
    if given ~= nil then
        return given
    end

    local ok, info = pcall(socket.peer, socket)

    if ok and type(info) == 'table' then
        return info.port
    end

    return nil
end

--- Поднимает TLS поверх открытого сокета.
---
--- При отказе освобождает всё, что успел завести, и оставляет сокет
--- вызывающему: закрыть чужой сокет за него — значит однажды закрыть
--- тот, который ему ещё нужен. Род отказа, если слой его назвал, идёт
--- третьим значением: по нему вызывающий решает, повторять ли.
---@param socket table Объект require('socket')
---@param settings TntTlsSettings
---@param backend table Слой FFI
---@return TntTlsLink|nil link
---@return string|nil err
---@return string|nil kind `outcome.UNTRUSTED`, если не принят сертификат сервера
function Module.establish(socket, settings, backend)
    local known, fd = pcall(socket.fd, socket)

    if not known or type(fd) ~= 'number' or fd < 0 then
        return nil,
            'у сокета нет дескриптора: он уже закрыт либо это не сокет'
    end

    local session, err = backend.open(fd, settings)

    if session == nil then
        return nil, err
    end

    local clocks = source()
    local deadline = clocks.monotonic() + settings.timeout

    while true do
        local state, why, kind = backend.handshake(session)

        if state == outcome.DONE then
            break
        end

        local wait

        if state == outcome.WANT_READ then
            wait = socket.readable
        elseif state == outcome.WANT_WRITE then
            wait = socket.writable
        else
            backend.release(session)

            return nil,
                why or ('рукопожатие TLS с %s оборвано другой стороной'):format(
                    settings.host
                ),
                kind
        end

        if not ready(socket, wait, deadline, clocks.scheduler_now) then
            backend.release(session)

            return nil,
                ('рукопожатие TLS с %s не уложилось в %s с'):format(
                    settings.host,
                    settings.timeout
                )
        end
    end

    return Module.new(socket, session, backend, settings)
end

--- Собирает объект соединения.
---
--- Отдельно от рукопожатия: так поведение чтения, записи и закрытия
--- проверяется на готовой сессии, без разговора о сертификатах.
---@param socket table
---@param session table
---@param backend table
---@param settings TntTlsSettings
---@return TntTlsLink
function Module.new(socket, session, backend, settings)
    --- Что прочитано, но ещё не отдано.
    local pending = ''

    --- Данных больше не будет: другая сторона закончила.
    local finished = false

    --- Соединение закрыто нами.
    local closed = false

    --- Чем договорились шифровать.
    ---
    --- Снимается сразу: после SSL_free спрашивать об этом уже не у кого,
    --- а в журнале отказа шифр нужен как раз тогда, когда соединение
    --- закрыто.
    local agreed = backend.describe(session)

    local port = Module.port_of(socket, settings.port)

    --- Читает столько, сколько просили.
    ---
    --- Возвращает кусок вместе с разделителем — как `socket:read`. Конец
    --- потока — не отказ: отдаётся накопленный хвост, и следующее чтение
    --- вернёт пустую строку. Так отличается «сервер закончил» от «сервер
    --- молчит», и построчный протокол видит эту разницу сам.
    ---@param opts table|number { delimiter = '\r\n' } либо { chunk = N }
    ---@param timeout number|nil
    ---@return string|nil
    ---@return string|nil err
    local function read(_, opts, timeout)
        if closed then
            return nil, 'соединение закрыто'
        end

        local request, wrong = buffer.request(opts)

        if request == nil then
            return nil, wrong
        end

        local clocks = source()
        local limit = tonumber(timeout) or settings.timeout
        local deadline = clocks.monotonic() + limit

        while true do
            local piece, rest, overflow = buffer.take(pending, request)

            if overflow ~= nil then
                return nil, overflow
            end

            if piece ~= nil then
                pending = rest

                return piece
            end

            if finished then
                local tail = pending

                pending = ''

                return tail
            end

            local state, data, why = backend.read(session)

            if state == outcome.DONE then
                pending = pending .. data
            elseif state == outcome.CLOSED then
                finished = true
            elseif state == outcome.WANT_READ or state == outcome.WANT_WRITE then
                local wait = state == outcome.WANT_READ and socket.readable or socket.writable

                if not ready(socket, wait, deadline, clocks.scheduler_now) then
                    return nil, ('%s не ответил за %s с'):format(settings.host, limit)
                end
            else
                return nil, why
            end
        end
    end

    --- Пишет строку целиком.
    ---
    --- Целиком, а не сколько получится: вызывающий пишет команду
    --- протокола, и половина команды — это сорванный разговор, а не
    --- частичный успех.
    ---@param text string
    ---@param timeout number|nil
    ---@return boolean
    ---@return string|nil err
    local function write(_, text, timeout)
        if closed then
            return false, 'соединение закрыто'
        end

        if type(text) ~= 'string' then
            return false, ('писать можно строку, а не %s'):format(type(text))
        end

        local clocks = source()
        local limit = tonumber(timeout) or settings.timeout
        local deadline = clocks.monotonic() + limit
        local sent = 0

        -- Условие стоит в начале цикла, а не после первого захода: пустая
        -- запись до OpenSSL не доходит вовсе. SSL_write нулевой длины
        -- не определён, и разные версии понимают его по-разному.
        while sent < #text do
            local state, written, why = backend.write(session, text, sent)

            if state == outcome.DONE then
                sent = sent + written
            elseif state == outcome.WANT_READ or state == outcome.WANT_WRITE then
                local wait = state == outcome.WANT_READ and socket.readable or socket.writable

                if not ready(socket, wait, deadline, clocks.scheduler_now) then
                    return false, ('%s не принял запись за %s с'):format(settings.host, limit)
                end
            elseif state == outcome.CLOSED then
                return false, ('%s закрыл соединение посреди записи'):format(settings.host)
            else
                return false, why
            end
        end

        return true
    end

    --- Закрывает соединение.
    ---
    --- Прощание двустороннее: своё close_notify и, по возможности, чужое.
    --- «По возможности» — потому что сервер вправе закрыть сокет сразу
    --- после своего, и повисший на чужом прощании файбер был бы хуже
    --- невежливости.
    ---
    --- Освобождение делается в любом случае, чем бы ни кончилось
    --- прощание: SSL и SSL_CTX не видит ни один счётчик Lua, и
    --- утечённые, они не найдутся никогда.
    local function close()
        if closed then
            return
        end

        closed = true

        local clocks = source()
        local deadline = clocks.monotonic() + math.min(SHUTDOWN_WAIT, settings.timeout)

        for _ = 1, SHUTDOWN_ROUNDS do
            local state = backend.shutdown(session)

            if state == outcome.DONE or state == outcome.FAILED then
                break
            end

            if state == outcome.WANT_READ or state == outcome.WANT_WRITE then
                local wait = state == outcome.WANT_READ and socket.readable or socket.writable

                if not ready(socket, wait, deadline, clocks.scheduler_now) then
                    break
                end
            elseif clocks.monotonic() >= deadline then
                break
            end
        end

        backend.release(session)

        -- Сокет закрывается здесь же: открыл его либо этот пакет,
        -- либо вызывающий, но после SSL_free он не годится ни на что,
        -- и оставленный открытым — это утёкший дескриптор.
        pcall(socket.close, socket)
    end

    --- Свободно ли соединение: ничего не пришло, и другая сторона его
    --- не закрыла.
    ---
    --- Без сети и без уступки — это вопрос пулу перед выдачей соединения,
    --- и ответ нужен сразу. Свободному соединению сервер обычно не шлёт
    --- ничего, а закрыв его, шлёт прощание TLS и конец потока. Смотреть
    --- надо в три места: в накопленное здесь, в OpenSSL — там лежат записи,
    --- уже взятые из сокета, — и в сам сокет. Сокет не читается, а только
    --- заглядывается (`MSG_PEEK`): прочитанную запись TLS назад в поток
    --- не вернуть, и соединение, признанное живым, после такого чтения
    --- было бы испорчено.
    ---
    --- Строже, чем нужно: служебная запись, которую сервер вправе прислать
    --- и живому соединению (новый билет сессии, смена ключей), тоже
    --- отвечает «не свободно». Цена ошибки в эту сторону — лишнее
    --- соединение, в другую — отказ на запросе, который уже ушёл.
    ---@return boolean
    local function idle()
        if closed or finished or pending ~= '' or backend.buffered(session) then
            return false
        end

        -- Под pcall: сокет, закрытый другим файбером, бросает, а это
        -- ответ «не свободно», а не повод ронять спросившего.
        local ok, piece = pcall(socket.recv, socket, 1, 'MSG_PEEK')

        return ok and piece == nil and socket:errno() == AGAIN
    end

    --- С кем и чем разговариваем. Для журнала и разбора: без шифра
    --- и версии протокола в записи «соединился» нельзя ни отличить
    --- TLS 1.2 от 1.3, ни заметить, что сервер сговорился на слабый шифр.
    ---@return { host: string, port: number|nil, cipher: string|nil, protocol: string|nil }
    local function peer()
        return {
            host = settings.host,
            port = port,
            cipher = agreed.cipher,
            protocol = agreed.protocol,
        }
    end

    return {
        read = read,
        write = write,
        close = close,
        idle = idle,
        peer = peer,
    }
end

return Module
