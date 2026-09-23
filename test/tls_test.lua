--- Тесты входа пакета: два способа поднять TLS и уборка за отказом.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.tls')

---@type any
local tls

---@type any
local outcome

g.before_each(function()
    tls = helper.load('tnt.tls')
    outcome = helper.module('tnt.tls.outcome')
end)

g.after_each(function()
    tls._set_source(nil)
    helper.unload()
end)

--- Ставит двойники сети и слоя FFI.
---@param plan table|nil Лист ответов слоя FFI
---@param answer table|nil Что отдаёт tcp_connect
---@return table log
---@return table asked Чего просили у сети
local function use_doubles(plan, answer)
    local backend, log = helper.backend(plan)
    local asked = {}

    tls._set_source({
        backend = function()
            return backend
        end,

        connect = function(host, port, timeout)
            asked.host = host
            asked.port = port
            asked.timeout = timeout

            if plan ~= nil and plan.connect_raises then
                error('getaddrinfo: nodename nor servname provided')
            end

            return answer, plan ~= nil and plan.connect_reason or nil
        end,
    })

    return log, asked
end

g.test_available_answers_yes_when_there_is_a_library = function()
    use_doubles()

    t.assert_equals(tls.available(), true)
end

g.test_available_names_the_places_where_it_looked = function()
    -- «TLS недоступен» в начале — это настройка, а посреди отправки
    -- письма — потерянное письмо.
    use_doubles({ library_error = 'OpenSSL не нашлась: libssl.so.3' })

    local ready, err = tls.available()

    t.assert_equals(ready, false)
    t.assert_str_contains(err, 'libssl.so.3')
end

g.test_connect_goes_to_the_named_host = function()
    local socket = helper.socket()
    local log, asked = use_doubles({ handshake = { { outcome.DONE } } }, socket)

    local link = tls.connect({ host = 'smtp.example.org', port = 465, timeout = 3 })

    t.assert_not_equals(link, nil)
    t.assert_equals(asked, { host = 'smtp.example.org', port = 465, timeout = 3 })
    t.assert_equals(
        log.settings.verify,
        true,
        'проверка сертификата включена по умолчанию'
    )
    t.assert_equals(log.settings.sni, 'smtp.example.org')
end

g.test_connect_checks_the_options_before_touching_the_network = function()
    local _, asked = use_doubles()

    t.assert_str_contains(select(2, tls.connect({ host = 'smtp.example.org' })), 'от 1 до 65535')
    t.assert_equals(asked.host, nil, 'до сети дело не дошло')
end

g.test_connect_tells_a_silent_host_from_an_unknown_one = function()
    use_doubles(nil, nil)

    t.assert_str_contains(
        select(2, tls.connect({ host = 'smtp.example.org', port = 465 })),
        'не открылось за 5 с'
    )
end

g.test_connect_names_the_reason_the_network_gave = function()
    -- «Connection refused» и «имя не разрешилось» чинятся по-разному,
    -- а без причины оба выглядели бы истёкшим сроком, хотя пришли
    -- мгновенно.
    use_doubles({ connect_reason = 'Connection refused' }, nil)

    t.assert_equals(
        select(2, tls.connect({ host = 'smtp.example.org', port = 465 })),
        'соединение с smtp.example.org:465 не открылось: Connection refused'
    )
end

g.test_connect_refuses_roots_that_are_not_a_path_before_the_network = function()
    local _, asked = use_doubles()

    t.assert_equals(
        select(2, tls.connect({ host = 'smtp.example.org', port = 465, ca_file = 123 })),
        'ca_file должен быть строкой, а не number'
    )
    t.assert_equals(asked.host, nil, 'до сети дело не дошло')
end

g.test_connect_does_not_fall_on_an_unresolvable_name = function()
    -- tcp_connect на негодном имени бывает, что не возвращает причину,
    -- а поднимает ошибку: ронять ею отправителя письма несоразмерно.
    use_doubles({ connect_raises = true })

    t.assert_str_contains(select(2, tls.connect({ host = 'нет.такого', port = 465 })), 'getaddrinfo')
end

g.test_connect_closes_the_socket_it_opened_itself = function()
    -- После сорванного рукопожатия сокет не годится ни на что,
    -- а оставленный открытым он утёкший дескриптор.
    local socket, state = helper.socket()
    local log = use_doubles(
        { handshake = { { outcome.FAILED, 'сертификат не принят', outcome.UNTRUSTED } } },
        socket
    )

    local link, err, kind = tls.connect({ host = 'smtp.example.org', port = 465 })

    t.assert_equals(link, nil)
    t.assert_equals(err, 'сертификат не принят')
    t.assert_equals(kind, tls.UNTRUSTED, 'род отказа дошёл до вызывающего')
    t.assert_equals(state.closed, true)
    t.assert_equals(log.released, 1)
end

g.test_the_word_of_an_untrusted_certificate_is_part_of_the_contract = function()
    -- Драйверы сверяют род строкой, не загружая пакет ради одного слова:
    -- сменить его — значит сломать их молча.
    t.assert_equals(tls.UNTRUSTED, 'untrusted')
    t.assert_equals(tls.UNTRUSTED, outcome.UNTRUSTED)
end

g.test_wrap_raises_tls_over_an_open_socket = function()
    -- Так работает STARTTLS: разговор начат открытым текстом.
    local socket = helper.socket({ peer_info = { host = '10.0.0.7', port = 587 } })
    local log = use_doubles({ handshake = { { outcome.DONE } } })

    local link = tls.wrap(socket, { host = 'smtp.example.org' })

    t.assert_not_equals(link, nil)
    t.assert_equals(log.settings.port, nil, 'порт у STARTTLS не нужен: сокет уже открыт')
    t.assert_equals(link:peer().port, 587, 'порт подсмотрен у сокета')
end

g.test_wrap_needs_a_socket = function()
    use_doubles()

    t.assert_str_contains(select(2, tls.wrap(nil, { host = 'smtp.example.org' })), 'нет сокета')
    t.assert_str_contains(select(2, tls.wrap('сокет', { host = 'smtp.example.org' })), 'нет сокета')
end

g.test_wrap_needs_a_host_name = function()
    -- Сокет своего имени не помнит, только адрес, а сертификат
    -- на адрес обычно не выписан.
    use_doubles()

    t.assert_str_contains(select(2, tls.wrap(helper.socket(), {})), 'нет host')
end

g.test_wrap_leaves_the_socket_to_its_owner = function()
    -- Закрыть чужой сокет за него значит однажды закрыть тот, который
    -- ему ещё нужен.
    local socket, state = helper.socket()
    local log = use_doubles({
        handshake = { { outcome.FAILED, 'не то имя в сертификате', outcome.UNTRUSTED } },
    })

    t.assert_equals(
        { tls.wrap(socket, { host = 'smtp.example.org' }) },
        { nil, 'не то имя в сертификате', 'untrusted' }
    )
    t.assert_equals(state.closed, false)
    t.assert_equals(log.released, 1, 'а вот своё освобождено')
end

g.test_verification_can_be_switched_off_by_the_caller = function()
    -- Осознанный выбор: шифрование без проверки защищает от
    -- подслушивания, но не от подмены.
    local log = use_doubles({ handshake = { { outcome.DONE } } }, helper.socket())

    tls.connect({ host = '127.0.0.1', port = 465, verify = false })

    t.assert_equals(log.settings.verify, false)
    t.assert_equals(log.settings.sni, nil, 'в SNI адрес не шлётся')
end

g.test_own_roots_reach_the_layer = function()
    local log = use_doubles({ handshake = { { outcome.DONE } } }, helper.socket())

    tls.connect({ host = 'smtp.example.org', port = 465, ca_file = '/своё.pem', sni = 'иное.имя' })

    t.assert_equals(log.settings.ca_file, '/своё.pem')
    t.assert_equals(log.settings.sni, 'иное.имя')
end

g.test_a_whole_line_talk_goes_through = function()
    -- Ради этого пакет и писался: построчный протокол поверх шифрования.
    local socket = helper.socket()
    local log = use_doubles({
        handshake = { { outcome.DONE } },
        write = { { outcome.DONE, 15 } },
        read = { { outcome.DONE, '250 принято\r\n' } },
        shutdown = { { outcome.DONE } },
    }, socket)

    local link = tls.connect({ host = 'smtp.example.org', port = 465, verify = false })

    t.assert_equals(link:write('MAIL FROM:<a>\r\n'), true)
    t.assert_equals(link:read({ delimiter = '\r\n' }), '250 принято\r\n')

    link:close()

    t.assert_equals(log.released, 1)
end
