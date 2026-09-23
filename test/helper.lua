--- Общие средства тестов пакета: загрузка исходников и двойники.
---
--- Двойников здесь три, и они разного уровня. Двойник сокета отвечает
--- на ожидания готовности; двойник слоя FFI отвечает состояниями по
--- заранее написанному листу — на нём проверяется всё поведение
--- соединения без OpenSSL вовсе; двойник самой OpenSSL отвечает так же,
--- как библиотека, вплоть до указателей и буферов, — на нём проверяются
--- ветки слоя FFI, которых на исправной машине не добиться.
---
--- Исходники читаются с диска, а не через `require`: у Tarantool свой
--- загрузчик `.rocks`, он идёт раньше `package.path` и подсунул бы
--- установленную копию пакета, если она есть. Проверки тогда шли бы
--- против вчерашнего кода, а покрытие считалось бы по нему. Зависимости
--- пакета — `tnt.clock`, `tnt.env`, `tnt.external` — берутся из `.rocks`
--- обычным `require`: проверяется этот пакет, а не они.
---
--- Оснастка в `test/testing/` — загрузчик исходников, работа без уступки
--- и сценарий ответов — грузится так же, файлами, и один раз на процесс:
--- второй экземпляр загрузчика не знал бы, что вытеснил первый, и не вернул
--- бы вытесненное на место.
---
--- Проверки берут всё через помощник, а не из оснастки напрямую: помощник —
--- единственное, чем файл проверок отличается от того же файла в наборе,
--- где пакет живёт рядом со своими зависимостями.

local errno = require('errno')
local ffi = require('ffi')
local fio = require('fio')

--- Модули оснастки в порядке зависимостей.
local TESTING = {
    { name = 'tnt.testing.sources', path = 'test/testing/sources.lua' },
    { name = 'tnt.testing.clock', path = 'test/testing/clock.lua' },
    { name = 'tnt.testing.protocol', path = 'test/testing/protocol.lua' },
}

for _, module in ipairs(TESTING) do
    if package.loaded[module.name] == nil then
        local chunk, failure = loadfile(fio.abspath(module.path))

        if chunk == nil then
            error(('оснастка %s не читается: %s'):format(module.name, tostring(failure)))
        end

        package.loaded[module.name] = chunk()
    end
end

--- Оснастка проверок под теми именами, что зовёт помощник.
local testing = {
    load_sources = package.loaded['tnt.testing.sources'].load,
    unload_sources = package.loaded['tnt.testing.sources'].unload,
    module = package.loaded['tnt.testing.sources'].module,
    work_without_yielding = package.loaded['tnt.testing.clock'].work_without_yielding,
    script = package.loaded['tnt.testing.protocol'].script,
}

local helper = {}

--- Модули пакета в порядке зависимостей.
helper.MODULES = {
    { name = 'tnt.tls.library', path = 'tnt/tls/library.lua' },
    { name = 'tnt.tls.outcome', path = 'tnt/tls/outcome.lua' },
    { name = 'tnt.tls.options', path = 'tnt/tls/options.lua' },
    { name = 'tnt.tls.buffer', path = 'tnt/tls/buffer.lua' },
    { name = 'tnt.tls.openssl', path = 'tnt/tls/openssl.lua' },
    { name = 'tnt.tls.link', path = 'tnt/tls/link.lua' },
    { name = 'tnt.tls', path = 'tnt/tls.lua' },
}

--- Загружает пакет и возвращает названный модуль.
---@param name string
---@return any
function helper.load(name)
    return testing.load_sources(helper.MODULES, name)
end

--- Уже загруженный модуль: пакета либо зависимости из `.rocks`.
helper.module = testing.module

--- Мир чтения окружения, в котором есть только названное проверкой.
---@param world { files: table<string, string>|nil, vars: table<string, string>|nil }
---@return table
local function world_of(world)
    local files = world.files or {}
    local vars = world.vars or {}

    return {
        getenv = function(name)
            return vars[name]
        end,

        exists = function(path)
            return files[path] ~= nil
        end,

        read = function(path)
            if files[path] == nil then
                return nil, 'нет такого файла'
            end

            return files[path]
        end,
    }
end

--- Настраивала ли проверка общее чтение окружения по своему миру.
local env_touched = false

--- Убирает загруженное.
---
--- Чтение окружения — установленное и одно на процесс, а не собранное
--- заново к каждой проверке: проверка, настроившая его по своему миру,
--- оставила бы свой `.env` соседям. Поэтому после неё оно настраивается
--- заново по пустому миру.
function helper.unload()
    testing.unload_sources(helper.MODULES)

    if env_touched then
        env_touched = false

        local env = require('tnt.env')

        env._set_source(world_of({}))
        env.configure()
        env._set_source(nil)
    end
end

--- Занимает файбер работой, не уступая управления: настоящие часы идут,
--- а отметка цикла событий стоит. Нужна проверкам срока рукопожатия.
helper.work_without_yielding = testing.work_without_yielding

--- Мир чтения окружения, в котором есть только названное проверкой:
--- `files` — что лежит на диске, `vars` — что задано при запуске.
---
--- Им подменяется чтение окружения `tnt-env`: путь к libssl слой FFI
--- спрашивает у него, и проверка строки в `.env` не должна зависеть
--- от того, что лежит рядом на машине.
---@param world { files: table<string, string>|nil, vars: table<string, string>|nil }
---@return table
function helper.env_world(world)
    env_touched = true

    return world_of(world)
end

---@class TntTlsFakeSocket
---@field fd_value integer Что отвечать на вопрос о дескрипторе
---@field ready boolean|nil Дожидается ли ожидание готовности
---@field raises boolean|nil Поднимать ли ошибку на ожидании
---@field tick fun()|nil Что сделать на каждом ожидании: обычно подвинуть часы
---@field peer_info table|nil Что отвечать про другую сторону
---@field peeked string|nil Что видно в сокете без чтения; пусто — ничего не пришло
---@field peek_errno integer|nil Что сказать о причине пустоты; по умолчанию EAGAIN
---@field peek_raises boolean|nil Поднимать ли ошибку, когда в сокет заглядывают
---@field closed boolean Закрывали ли сокет
---@field waits table[] Чего и сколько ждали
---@field peeks table[] С каким размером и флагами заглядывали в сокет

--- Двойник сокета.
---
--- Ожидания готовности записываются: проверка сроков смотрит не только
--- на отказ, но и на то, сколько именно соединение соглашалось ждать.
---@param state TntTlsFakeSocket|nil
---@return table socket
---@return TntTlsFakeSocket state
function helper.socket(state)
    ---@type any
    local fake = state or {}

    fake.fd_value = fake.fd_value or 7
    fake.closed = false
    fake.waits = {}
    fake.peeks = {}

    local function wait(kind)
        return function(_, timeout)
            table.insert(fake.waits, { kind = kind, timeout = timeout })

            if fake.raises then
                error('сокет закрыт другим файбером')
            end

            -- Крючок для проверок сроков: ожидание — единственное место,
            -- где у настоящего соединения проходит время.
            if fake.tick ~= nil then
                fake.tick()
            end

            return fake.ready ~= false
        end
    end

    local socket = {
        fd = function()
            return fake.fd_value
        end,

        readable = wait('readable'),
        writable = wait('writable'),

        peer = function()
            if fake.peer_info == nil then
                error('сокет уже закрыт')
            end

            return fake.peer_info
        end,

        -- Заглядывание в сокет без чтения: так соединение спрашивает,
        -- свободно ли оно.
        recv = function(_, size, flags)
            table.insert(fake.peeks, { size = size, flags = flags })

            if fake.peek_raises then
                error('сокет закрыт другим файбером')
            end

            return fake.peeked
        end,

        errno = function()
            return fake.peek_errno or errno.EAGAIN
        end,

        close = function()
            fake.closed = true
        end,
    }

    return socket, fake
end

--- Двойник слоя FFI: отвечает состояниями по листу.
---
--- Лист — очередь ответов на каждое действие. Кончившаяся очередь —
--- ошибка теста, а не молчаливый успех: проверка, в которой соединение
--- сходило к слою лишний раз, обязана об этом сказать.
---@param plan table|nil
---@return table backend
---@return table log
function helper.backend(plan)
    ---@type any
    local script = plan or {}

    local log = { opened = 0, released = 0, writes = {}, describes = 0 }

    -- Лист каждого действия — сценарий оснастки: кончившийся сценарий
    -- бросает сам.
    local queues = {
        handshake = testing.script(script.handshake or { { 'done' } }),
        read = testing.script(script.read or {}),
        write = testing.script(script.write or {}),
        shutdown = testing.script(script.shutdown or { { 'done' } }),
    }

    local function step(name)
        return queues[name].next()
    end

    local backend = {
        library = function()
            if script.library_error ~= nil then
                return nil, script.library_error
            end

            return script.library or {}
        end,

        open = function(fd, settings)
            log.opened = log.opened + 1
            log.fd = fd
            log.settings = settings

            if script.open_error ~= nil then
                return nil, script.open_error
            end

            return { alive = true }
        end,

        handshake = function()
            local answer = step('handshake')

            return answer[1], answer[2], answer[3]
        end,

        read = function()
            local answer = step('read')

            return answer[1], answer[2], answer[3]
        end,

        write = function(_, text, sent)
            table.insert(log.writes, { text = text, sent = sent })

            local answer = step('write')

            return answer[1], answer[2], answer[3]
        end,

        shutdown = function()
            return step('shutdown')[1]
        end,

        release = function(session)
            log.released = log.released + 1
            session.alive = false
        end,

        describe = function()
            log.describes = log.describes + 1

            return script.describe or { protocol = 'TLSv1.3', cipher = 'TLS_AES_256_GCM_SHA384' }
        end,

        buffered = function()
            return script.buffered == true
        end,
    }

    return backend, log
end

--- Двойник самой OpenSSL.
---
--- Отвечает указателями и заполняет буферы так же, как настоящая
--- библиотека: иначе слой FFI пришлось бы проверять только против
--- живого сервера, а ветки вроде «SSL_CTX_new вернула пустоту» на
--- исправной машине не случаются никогда.
---@param plan table|nil
---@return table lib
---@return table log
function helper.libssl(plan)
    ---@type any
    local script = plan or {}

    local log = { freed_ssl = 0, freed_ctx = 0, written = {}, verify_mode = nil, host = nil, sni = nil, identity = {} }

    -- Строки, на которые отдаются указатели, держатся здесь: без ссылки
    -- сборщик убрал бы их, и указатель смотрел бы в никуда.
    local anchors = {}

    local function text_of(value)
        table.insert(anchors, value)

        return ffi.cast('const char *', value)
    end

    local function pointer(present, address)
        return ffi.cast('void *', present and (address or 1) or 0)
    end

    --- Строка, как бы её ни передали.
    ---
    --- Двойник — обычная функция Lua, и превращения аргументов в C с ней
    --- не происходит: строка приходит строкой, а указатель указателем.
    ---@param value any
    ---@return string|nil
    local function plain(value)
        if value == nil or type(value) == 'string' then
            return value
        end

        return ffi.string(value)
    end

    local queues = {
        connect = script.connect or { 1 },
        read = script.read or {},
        write = script.write or {},
        shutdown = script.shutdown or { 1 },
        errors = script.errors or {},
    }

    local lib = {
        TLS_client_method = function()
            return pointer(true)
        end,

        SSL_CTX_new = function()
            return pointer(script.no_context ~= true)
        end,

        SSL_CTX_free = function()
            log.freed_ctx = log.freed_ctx + 1
        end,

        SSL_CTX_ctrl = function(_, cmd, larg)
            log['ctx_ctrl_' .. tostring(cmd)] = larg

            return 1
        end,

        SSL_CTX_set_default_verify_paths = function()
            log.default_roots = true

            return script.no_default_roots and 0 or 1
        end,

        SSL_CTX_load_verify_locations = function(_, ca_file, ca_path)
            log.ca_file = plain(ca_file)
            log.ca_path = plain(ca_path)

            return script.no_roots and 0 or 1
        end,

        -- Сертификат клиента: шаги пишутся по порядку, чтобы было видно,
        -- что пустой пароль встал раньше, чем читается ключ.
        SSL_CTX_use_certificate_chain_file = function(_, file)
            table.insert(log.identity, 'chain')
            log.cert_file = plain(file)

            return script.no_cert and 0 or 1
        end,

        SSL_CTX_set_default_passwd_cb_userdata = function(_, password)
            table.insert(log.identity, 'password')
            log.password = plain(password)
        end,

        SSL_CTX_use_PrivateKey_file = function(_, file, kind)
            table.insert(log.identity, 'key')
            log.key_file = plain(file)
            log.key_kind = kind

            return script.no_key and 0 or 1
        end,

        SSL_CTX_check_private_key = function()
            table.insert(log.identity, 'check')

            return script.no_match and 0 or 1
        end,

        SSL_has_pending = function()
            return script.pending or 0
        end,

        SSL_new = function()
            return pointer(script.no_ssl ~= true, 2)
        end,

        SSL_free = function()
            log.freed_ssl = log.freed_ssl + 1
        end,

        SSL_set_fd = function(_, fd)
            log.fd = fd

            return script.no_fd and 0 or 1
        end,

        SSL_ctrl = function(_, cmd, larg, parg)
            log.sni = plain(ffi.cast('const char *', parg))
            log.sni_cmd = cmd
            log.sni_type = larg

            return 1
        end,

        SSL_set1_host = function(_, host)
            log.host = plain(host)

            return script.no_host and 0 or 1
        end,

        SSL_set_verify = function(_, mode)
            log.verify_mode = mode
        end,

        SSL_connect = function()
            return table.remove(queues.connect, 1) or -1
        end,

        SSL_read = function(_, buffer, size)
            log.read_size = size

            local answer = table.remove(queues.read, 1)

            if type(answer) ~= 'string' then
                return answer or -1
            end

            assert(#answer <= size, 'двойник отдаёт больше, чем просили')
            ffi.copy(buffer, answer, #answer)

            return #answer
        end,

        SSL_write = function(_, from, size)
            table.insert(log.written, ffi.string(from, size))

            local answer = table.remove(queues.write, 1)

            return answer or size
        end,

        SSL_shutdown = function()
            return table.remove(queues.shutdown, 1) or 1
        end,

        SSL_get_error = function()
            return script.error_code or 1
        end,

        SSL_get_verify_result = function()
            return script.verify_result or 0
        end,

        SSL_get_version = function()
            return text_of(script.protocol or 'TLSv1.3')
        end,

        SSL_get_current_cipher = function()
            return pointer(script.no_cipher ~= true)
        end,

        SSL_CIPHER_get_name = function()
            return text_of(script.cipher or 'TLS_AES_256_GCM_SHA384')
        end,

        ERR_get_error = function()
            return table.remove(queues.errors, 1) or 0
        end,

        ERR_error_string_n = function(code, buffer, size)
            log.error_text_size = size

            local message = ('error:%s'):format(tostring(code))

            assert(#message < size, 'двойник отдаёт строку длиннее буфера')
            ffi.copy(buffer, message, #message + 1)
        end,

        ERR_clear_error = function()
            log.cleared = (log.cleared or 0) + 1
        end,

        X509_verify_cert_error_string = function()
            return text_of(script.verify_text or 'self-signed certificate')
        end,
    }

    return lib, log
end

return helper
