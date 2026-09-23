--- Тесты против настоящего сервера TLS.
---
--- Двойников здесь нет намеренно. Всё, что проверяется двойниками, —
--- это договор, который пакет сам себе назначил; а шифрование либо
--- работает с чужой машиной, либо не работает, и узнать это можно
--- только у чужой машины. Сервер поднимается свой: `openssl s_server`
--- с самоподписанным сертификатом во временном каталоге.
---
--- Серверов три, потому что разговоры разные. `-rev` отвечает на каждую
--- строку её же наизнанку — на нём проверяется, что данные ходят в обе
--- стороны. `-www` отдаёт ответ HTTP, в котором строки оканчиваются
--- CRLF, — на нём проверяется чтение по разделителю и по размеру так,
--- как его делают почтовые протоколы. Третий — тот же `-rev`, но
--- требующий сертификат клиента (`-Verify`): доверяет он одному
--- сертификату, выписанному здесь же для клиента.
---
--- Тест умеет пропуститься: без `openssl` в системе и без библиотеки
--- OpenSSL проверять нечего. Но пропуск — это отсутствие проверки,
--- и подсказка говорит, чего именно не хватает.

local t = require('luatest')
local fiber = require('fiber')
local fio = require('fio')
local popen = require('popen')
--- Сеть. Через any: проверке нужен и вызов самого модуля, которым
--- заводят голый сокет, и методы такого сокета, — а объявленных типов
--- ни на то, ни на другое нет.
---@type any
local socket = require('socket')

local helper = dofile('test/helper.lua')

-- Рок `http` объявляет часть тех же функций OpenSSL своими подписями,
-- и на узле с сервером HTTP его объявления приходят в процесс раньше
-- пакета — ffi оставляет в силе первое. Он грузится здесь, до пакета,
-- чтобы живые проверки шли в том же положении: подпись, не совпавшая
-- с его, иначе ломалась бы только в бою. Без рока проверки идут как есть.
pcall(require, 'http.sslsocket')

local g = t.group('tnt.tls.live')

--- Сколько ждать, пока сервер начнёт слушать.
local STARTUP_WAIT = 10

--- Сколько соединений подряд считается достаточным для проверки утечки.
local CONNECTIONS = 100

--- Насколько позволено вырасти памяти процесса за эти соединения.
---
--- Мегабайт. Число не с потолка: исправный пакет вырастает здесь
--- на 16–32 КиБ, а тот же пакет с отключённым освобождением — на девять
--- мегабайт, потому что каждый утёкший SSL_CTX тянет за собой
--- прочитанное хранилище доверенных корней. Мегабайт лежит на порядок
--- выше разброса и на порядок ниже утечки: проверка не мигает и всё же
--- ловит то, ради чего написана.
local MEMORY_HEADROOM = 1024

---@type any
local tls

--- Почему проверять нечего, если нечего.
---@type string|nil
local hopeless

--- Временный каталог с сертификатом и ключом.
---@type string|nil
local workdir

--- Запущенные серверы: порт и ручка процесса.
---@type table<string, table>
local servers = {}

--- Файл во временном каталоге.
---@param name string
---@return string
local function inside(name)
    return fio.pathjoin(workdir, name)
end

--- Оболочка: она одна умеет искать команду по PATH.
---
--- popen.new запускает то, что назвали, без поиска по PATH, и голое имя
--- «openssl» до него не доходит. Поэтому путь к нему спрашивается
--- у оболочки один раз, а дальше запуск идёт прямой.
local SHELL = '/bin/sh'

--- Запускает команду и ждёт её конца.
---@param argv string[]
---@return boolean ok
---@return string|nil output
local function run(argv)
    local started, handle = pcall(popen.new, argv, {
        stdin = popen.opts.DEVNULL,
        stdout = popen.opts.PIPE,
        stderr = popen.opts.DEVNULL,
    })

    if not started or handle == nil then
        return false, tostring(handle)
    end

    local output = handle:read({ timeout = 30 })
    local status = handle:wait()

    handle:close()

    return status.exit_code == 0, output
end

--- Выполняет строку оболочкой.
---@param command string
---@return boolean ok
---@return string|nil output
local function shell(command)
    return run({ SHELL, '-c', command })
end

--- Где лежит названная программа.
---@param name string
---@return string|nil
local function which(name)
    local ok, output = shell(('command -v %s'):format(name))

    if not ok or output == nil then
        return nil
    end

    local path = output:gsub('%s+$', '')

    return path ~= '' and path or nil
end

--- Путь к openssl, найденный один раз.
---@type string|nil
local openssl_bin = nil

--- Свободный порт.
---
--- Спрашивается у ядра, а не назначается числом: занятый порт превратил
--- бы проверку в мигающую, а мигающую проверку выключают.
---@return number
local function free_port()
    local probe = socket('AF_INET', 'SOCK_STREAM', 'tcp')

    probe:bind('127.0.0.1', 0)

    local port = probe:name().port

    probe:close()

    return tonumber(port) or 0
end

--- Дожидается, пока по порту начнут отвечать.
---@param port number
---@return boolean
local function listening(port)
    local deadline = fiber.clock() + STARTUP_WAIT

    while fiber.clock() < deadline do
        local probe = socket.tcp_connect('127.0.0.1', port, 0.2)

        if probe ~= nil then
            probe:close()

            return true
        end

        fiber.sleep(0.05)
    end

    return false
end

--- Поднимает `openssl s_server` с нашим сертификатом.
---@param name string Как его звать в проверках
---@param mode string[] Ключи, задающие поведение: -rev либо -www, и прочие
---@return boolean
local function serve(name, mode)
    local port = free_port()

    local argv = {
        openssl_bin,
        's_server',
        '-accept',
        tostring(port),
        '-cert',
        inside('cert.pem'),
        '-key',
        inside('key.pem'),
        '-quiet',
    }

    for _, flag in ipairs(mode) do
        table.insert(argv, flag)
    end

    local handle = popen.new(argv, {
        stdin = popen.opts.DEVNULL,
        stdout = popen.opts.DEVNULL,
        stderr = popen.opts.DEVNULL,
    })

    servers[name] = { port = port, handle = handle }

    return listening(port)
end

--- Сколько памяти занимает процесс, в килобайтах.
---@return number|nil
local function resident_memory()
    -- Через $PPID: своего номера процесса Tarantool из Lua не называет,
    -- а родителем оболочки будет как раз он.
    local ok, output = shell('ps -o rss= -p $PPID')

    if not ok or output == nil then
        return nil
    end

    return tonumber((output:gsub('%s', '')))
end

--- Память процесса либо пропуск: без ps мерить утечку нечем.
---@return number
local function memory_now()
    local kilobytes = resident_memory()

    t.skip_if(kilobytes == nil, 'ps не сказал, сколько памяти занимает процесс')

    return kilobytes or 0
end

--- Опции соединения с поднятым сервером.
---@param name string
---@param overrides table|nil
---@return table
local function opts(name, overrides)
    local chosen = { host = '127.0.0.1', port = servers[name].port, timeout = 5, verify = false }

    for key, value in pairs(overrides or {}) do
        chosen[key] = value
    end

    return chosen
end

--- Путь к сертификату, который здесь же и выписан.
---@return string
local function own_root()
    return fio.pathjoin(workdir, 'cert.pem')
end

g.before_all(function()
    tls = helper.load('tnt.tls')

    openssl_bin = which('openssl')

    if openssl_bin == nil or not run({ openssl_bin, 'version' }) then
        hopeless =
            'в системе нет openssl: поставьте его (brew install openssl@3 либо пакет openssl)'

        return
    end

    local ready, err = tls.available()

    if not ready then
        hopeless = tostring(err)

        return
    end

    workdir = fio.tempdir()

    -- Имя узла кладётся и в subjectAltName: современная проверка имени
    -- смотрит туда, а на CN оглядывается только за неимением другого.
    local issued = run({
        openssl_bin,
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-keyout',
        fio.pathjoin(workdir, 'key.pem'),
        '-out',
        fio.pathjoin(workdir, 'cert.pem'),
        '-days',
        '1',
        '-nodes',
        '-subj',
        '/CN=localhost',
        '-addext',
        'subjectAltName=DNS:localhost',
    })

    if not issued then
        hopeless = 'openssl не выписал самоподписанный сертификат'

        return
    end

    -- Клиенту — свой сертификат, выписанный только на вход клиента:
    -- требовательный сервер доверяет ему одному. К нему — ключ другого
    -- рода (EC при сертификате RSA), его же ключ под паролем и один файл
    -- с сертификатом и ключом вместе.
    local client = run({
        openssl_bin,
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-keyout',
        inside('client.key'),
        '-out',
        inside('client.pem'),
        '-days',
        '1',
        '-nodes',
        '-subj',
        '/CN=tnt-tls-live-client',
        '-addext',
        'extendedKeyUsage=clientAuth',
    }) and run({
        openssl_bin,
        'genpkey',
        '-algorithm',
        'EC',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-out',
        inside('stranger.key'),
    }) and run({
        openssl_bin,
        'pkey',
        '-in',
        inside('client.key'),
        '-aes256',
        '-passout',
        'pass:secret',
        '-out',
        inside('locked.key'),
    })

    if not client then
        hopeless = 'openssl не выписал сертификат и ключи клиента'

        return
    end

    -- Пути оболочке без кавычек: во временном каталоге пробелов нет.
    if not shell(('cat %s %s > %s'):format(inside('client.pem'), inside('client.key'), inside('bundle.pem'))) then
        hopeless = 'не собрался файл с сертификатом и ключом клиента'

        return
    end

    local demanding = { '-rev', '-Verify', '1', '-verify_return_error', '-CAfile', inside('client.pem') }

    if not serve('echo', { '-rev' }) or not serve('pages', { '-www' }) or not serve('demanding', demanding) then
        hopeless = 'openssl s_server не начал слушать'
    end
end)

g.after_all(function()
    for _, server in pairs(servers) do
        if server.handle ~= nil then
            pcall(server.handle.kill, server.handle)
            pcall(server.handle.close, server.handle)
        end
    end

    servers = {}

    if workdir ~= nil then
        fio.rmtree(workdir)
    end

    helper.unload()
end)

g.before_each(function()
    t.skip_if(hopeless ~= nil, hopeless)
end)

g.test_handshake_passes_and_data_goes_both_ways = function()
    local link, err = tls.connect(opts('echo'))

    t.assert_equals(err, nil)
    t.assert_not_equals(link, nil)

    local peer = link:peer()

    t.assert_equals(peer.host, '127.0.0.1')
    t.assert_equals(peer.port, servers.echo.port)
    t.assert_str_contains(peer.protocol, 'TLS', 'договорились именно о TLS')
    t.assert_not_equals(peer.cipher, nil, 'и о шифре')

    t.assert_equals(link:write('abcdef\r\n'), true)

    -- Сервер отвечает строкой наизнанку: значит, наше дошло целиком
    -- и расшифровалось, а его пришло и расшифровалось у нас.
    t.assert_equals(link:read({ delimiter = '\n' }, 5), 'fedcba\n')

    link:close()
end

g.test_self_signed_certificate_is_refused_with_a_reason = function()
    -- Молчаливый успех здесь был бы худшим из возможных исходов: канал
    -- зашифрован, а с кем — неизвестно.
    local link, err, kind = tls.connect(opts('echo', { host = 'localhost', verify = true }))

    t.assert_equals(link, nil)
    t.assert_str_contains(err, 'сертификат не принят')
    t.assert_str_contains(err, 'self-signed certificate')
    t.assert_equals(
        kind,
        tls.UNTRUSTED,
        'отказ, который время не лечит, назван словом'
    )
end

g.test_the_same_certificate_passes_without_verification = function()
    -- Осознанный выбор вызывающего: свой сервер в своём контуре.
    local link, err = tls.connect(opts('echo', { host = 'localhost', verify = false }))

    t.assert_equals(err, nil)
    t.assert_not_equals(link, nil)

    link:close()
end

g.test_own_root_makes_the_same_certificate_trusted = function()
    -- Нужен как опора для следующей проверки: если и с доверенным корнем
    -- соединение не встаёт, отказ по имени ничего не доказывает.
    local link, err = tls.connect(opts('echo', { host = 'localhost', verify = true, ca_file = own_root() }))

    t.assert_equals(err, nil)
    t.assert_not_equals(link, nil)

    link:close()
end

g.test_wrong_host_name_is_refused = function()
    -- Сертификат выписан на localhost, а соединяемся по адресу. Корень
    -- доверенный, шифрование поднялось бы — не сходится только имя,
    -- и именно на этом всё обязано встать.
    local link, err, kind = tls.connect(opts('echo', { host = '127.0.0.1', verify = true, ca_file = own_root() }))

    t.assert_equals(link, nil)
    t.assert_str_contains(err, 'сертификат не принят')
    t.assert_str_contains(err, 'mismatch')
    t.assert_equals(kind, tls.UNTRUSTED)
end

g.test_a_silent_server_is_refused_by_the_deadline = function()
    -- Сервер молчит, пока ему не напишут. Чтение обязано отказать
    -- по сроку, а не висеть.
    local link = tls.connect(opts('echo'))

    local started = fiber.clock()
    local line, err = link:read({ delimiter = '\r\n' }, 0.5)
    local spent = fiber.clock() - started

    t.assert_equals(line, nil)
    t.assert_str_contains(err, 'не ответил за 0.5 с')
    t.assert_almost_equals(spent, 0.5, 0.5, 'срок соблюдён, а не пересижен')

    link:close()
end

g.test_a_waiting_fiber_does_not_stop_the_others = function()
    -- Главное свойство пакета. Блокирующий SSL_read на общем потоке
    -- остановил бы весь узел: и репликацию, и отклик на iproto,
    -- и пробы живости.
    local ticks = 0

    local ticker = fiber.create(function()
        while true do
            ticks = ticks + 1
            fiber.sleep(0.01)
        end
    end)

    ticker:set_joinable(true)

    local link = tls.connect(opts('echo'))

    link:read({ delimiter = '\r\n' }, 1)

    ticker:cancel()

    link:close()

    t.assert_gt(
        ticks,
        20,
        'пока одно соединение ждало, соседний файбер работал'
    )
end

g.test_reading_by_delimiter_and_by_size_works_as_on_a_plain_socket = function()
    local link = tls.connect(opts('pages'))

    t.assert_equals(link:write('GET / HTTP/1.0\r\n\r\n'), true)

    -- По разделителю: строка отдаётся вместе с CRLF, как это делает
    -- socket:read, — построчные протоколы рассчитаны именно на это.
    t.assert_equals(link:read({ delimiter = '\r\n' }, 5), 'HTTP/1.0 200 ok\r\n')

    -- По размеру: ровно столько байт, сколько попросили, и ни байтом
    -- больше. Так читается тело письма, внутри которого есть и CRLF.
    t.assert_equals(link:read({ chunk = 8 }, 5), 'Content-')
    t.assert_equals(link:read({ delimiter = '\r\n' }, 5), 'type: text/html\r\n')

    link:close()
end

g.test_wrap_raises_tls_over_a_socket_that_is_already_open = function()
    -- Тот же путь, которым идёт STARTTLS: сокет открыт заранее,
    -- шифрование поднимается поверх него.
    local plain = socket.tcp_connect('127.0.0.1', servers.echo.port, 5)

    t.assert_not_equals(plain, nil)

    local link, err = tls.wrap(plain, { host = 'localhost', verify = false, timeout = 5 })

    t.assert_equals(err, nil)
    t.assert_equals(link:write('12345\r\n'), true)
    t.assert_equals(link:read({ delimiter = '\n' }, 5), '54321\n')
    t.assert_equals(link:peer().port, servers.echo.port, 'порт подсмотрен у сокета')

    link:close()
end

g.test_a_hundred_connections_neither_fall_nor_leak = function()
    -- Утечка SSL_CTX не видна ни одному счётчику Lua: заметить её можно
    -- только по памяти процесса.
    local first = tls.connect(opts('echo'))

    first:close()

    collectgarbage('collect')

    local before = memory_now()

    for index = 1, CONNECTIONS do
        local link, err = tls.connect(opts('echo'))

        t.assert_not_equals(link, nil, ('соединение %s не встало: %s'):format(index, tostring(err)))
        t.assert_equals(link:write('abc\r\n'), true)
        t.assert_equals(link:read({ delimiter = '\n' }, 5), 'cba\n')

        link:close()
    end

    collectgarbage('collect')

    local after = memory_now()

    t.assert_lt(
        after - before,
        MEMORY_HEADROOM,
        ('память выросла на %s КиБ за %s соединений'):format(after - before, CONNECTIONS)
    )
end

g.test_a_forgotten_connection_is_freed_by_the_collector = function()
    -- Освобождение вешается на сборщик сразу при заведении: забытое
    -- соединение обязано быть отпущено, пусть и позже.
    local before = memory_now()

    for _ = 1, 20 do
        t.assert_not_equals(tls.connect(opts('echo')), nil)

        -- Ссылка не сохраняется и close не зовётся: соединение брошено.
        collectgarbage('collect')
    end

    collectgarbage('collect')

    t.assert_lt(
        memory_now() - before,
        MEMORY_HEADROOM,
        ('брошенные соединения не отпущены: память выросла на %s КиБ'):format(
            memory_now() - before
        )
    )
end

--- Строка туда и наизнанку обратно: соединение встало и говорит.
---@param link any
---@param text string
local function talks(link, text)
    t.assert_equals(link:write(text .. '\r\n'), true)
    t.assert_equals(link:read({ delimiter = '\n' }, 5), text:reverse() .. '\n')
end

g.test_a_client_certificate_opens_a_server_that_demands_it = function()
    local link, err =
        tls.connect(opts('demanding', { cert_file = inside('client.pem'), key_file = inside('client.key') }))

    t.assert_equals(err, nil)
    talks(link, 'abcdef')

    link:close()
end

g.test_one_file_with_the_certificate_and_the_key_is_enough = function()
    local link, err = tls.connect(opts('demanding', { cert_file = inside('bundle.pem') }))

    t.assert_equals(err, nil)
    talks(link, 'bundle')

    link:close()
end

g.test_without_a_certificate_the_demanding_server_refuses = function()
    -- В TLS 1.3 рукопожатие у клиента кончается раньше, чем сервер
    -- проверит его сертификат, и отказ приходит первым чтением; в TLS 1.2 —
    -- самим рукопожатием. Молча соединиться не должно ни там, ни там.
    --
    -- Сертификат сервера здесь проверяется и принимается: отказывает
    -- сервер, не получивший нашего, и винить словом `untrusted` его
    -- сертификат было бы неправдой.
    local link, err, kind = tls.connect(opts('demanding', { host = 'localhost', verify = true, ca_file = own_root() }))

    t.assert_equals(kind, nil)

    if link ~= nil then
        link:write('abc\r\n')

        local line, why = link:read({ delimiter = '\n' }, 5)

        t.assert_equals(line, nil)
        err = why
        link:close()
    end

    t.assert_str_contains(err, 'certificate required')
end

g.test_a_key_of_another_kind_is_refused_before_the_handshake = function()
    -- Ключ EC при сертификате RSA OpenSSL принимает молча: не сверь
    -- их отдельным шагом — отказ пришёл бы от сервера, без слова о ключе.
    local link, err =
        tls.connect(opts('demanding', { cert_file = inside('client.pem'), key_file = inside('stranger.key') }))

    t.assert_equals(link, nil)
    t.assert_str_contains(
        err,
        ('сопоставление ключа %s с сертификатом %s не удалось: '):format(
            inside('stranger.key'),
            inside('client.pem')
        )
    )
end

g.test_a_key_under_a_password_is_refused_at_once = function()
    -- Без пустого пароля OpenSSL спросила бы пароль у терминала, и узел,
    -- запущенный из терминала, встал бы, ожидая ответа.
    local started = fiber.clock()
    local link, err =
        tls.connect(opts('demanding', { cert_file = inside('client.pem'), key_file = inside('locked.key') }))

    t.assert_equals(link, nil)
    t.assert_str_contains(
        err,
        ('чтение ключа клиента %s не удалось: '):format(inside('locked.key'))
    )
    t.assert_lt(fiber.clock() - started, 1)
end

g.test_a_missing_certificate_file_is_named = function()
    local link, err = tls.connect(opts('demanding', { cert_file = inside('nobody.pem') }))

    t.assert_equals(link, nil)
    t.assert_str_contains(
        err,
        ('чтение сертификата клиента %s не удалось: '):format(inside('nobody.pem'))
    )
    t.assert_str_contains(err, 'No such file or directory')
end

g.test_a_talked_connection_is_idle_until_the_server_closes_it = function()
    -- Служебные записи после рукопожатия (билеты сессии TLS 1.3) снимает
    -- первое же чтение ответа: после разговора соединение свободно.
    local link = tls.connect(opts('echo'))

    talks(link, 'idle')
    t.assert_equals(link:idle(), true)
    t.assert_equals(link:idle(), true, 'заглядывание ничего не вынимает из сокета')

    -- Сервер закрывает соединение по слову CLOSE: шлёт прощание TLS
    -- и закрывает сокет — так же, как сервер, закрывший простаивающее.
    t.assert_equals(link:write('CLOSE\r\n'), true)
    t.helpers.retrying({ timeout = 5 }, function()
        t.assert_equals(link:idle(), false)
    end)

    link:close()
end

g.test_peeking_leaves_the_answer_to_the_reader = function()
    -- Пришедший ответ заглядывание не портит: соединение не свободно,
    -- а читающий получает ответ целиком.
    local link = tls.connect(opts('echo'))

    t.assert_equals(link:write('peek\r\n'), true)
    t.helpers.retrying({ timeout = 5 }, function()
        t.assert_equals(link:idle(), false)
    end)
    t.assert_equals(link:read({ delimiter = '\n' }, 5), 'keep\n')

    link:close()
end
