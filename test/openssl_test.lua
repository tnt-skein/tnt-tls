--- Тесты слоя FFI: настройка соединения и разбор ответов библиотеки.
---
--- Библиотека подменена двойником, который отвечает так же, как
--- настоящая, — указателями и заполненными буферами. Иначе ветки вроде
--- «SSL_CTX_new вернула пустоту» или «доверенные корни не прочитались»
--- проверить нечем: на исправной машине они не случаются никогда,
--- а случаются они на чужой, где всё и ломается.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.tls.openssl')

---@type any
local openssl

---@type any
local outcome

g.before_each(function()
    openssl = helper.load('tnt.tls.openssl')
    outcome = helper.module('tnt.tls.outcome')
end)

g.after_each(function()
    openssl._set_source(nil)
    openssl.forget()
    helper.unload()
end)

--- Ставит двойник библиотеки на место настоящей.
---@param plan table|nil
---@return table lib
---@return table log
local function use_library(plan)
    local lib, log = helper.libssl(plan)

    openssl._set_source({
        open = function()
            return lib
        end,
    })

    return lib, log
end

--- Настройки соединения.
---@param overrides table|nil
---@return table
local function settings(overrides)
    local chosen = { host = 'mail.example.org', port = 993, timeout = 5, verify = true, sni = 'mail.example.org' }

    for name, value in pairs(overrides or {}) do
        chosen[name] = value
    end

    return chosen
end

g.test_library_is_loaded_once = function()
    -- Единственное состояние, общее для соединений: dlopen одного и того
    -- же файла на каждое соединение не дал бы ничего, кроме работы.
    local loads = 0

    openssl._set_source({
        open = function()
            loads = loads + 1

            return { name = 'libssl' }
        end,
    })

    t.assert_equals(openssl.library().name, 'libssl')
    t.assert_equals(openssl.library().name, 'libssl')
    t.assert_equals(loads, 1)
end

g.test_absent_library_is_remembered_too = function()
    -- Перебирать десяток путей на каждое письмо незачем: раз не нашлась,
    -- второй раз не найдётся.
    local attempts = 0

    openssl._set_source({
        open = function()
            attempts = attempts + 1

            error('нет такой библиотеки')
        end,
    })

    local lib, err = openssl.library()

    t.assert_equals(lib, nil)
    t.assert_str_contains(err, 'OpenSSL не нашлась')

    local first = attempts
    local again, again_err = openssl.library()

    t.assert_equals(attempts, first, 'второй раз не перебирается')
    t.assert_equals(again, nil)
    t.assert_equals(again_err, err, 'и причина та же')
end

g.test_environment_variable_points_the_way = function()
    local asked = nil

    openssl._set_source({
        getenv = function(name)
            asked = name

            return '/своя/libssl.so'
        end,

        open = function(name)
            t.assert_equals(name, '/своя/libssl.so')

            return { name = name }
        end,
    })

    t.assert_not_equals(openssl.library(), nil)
    t.assert_equals(asked, 'TNT_TLS_LIBSSL')
end

g.test_the_path_is_read_through_the_environment_reader = function()
    -- Без подмены внешней зависимости путь спрашивается у `tnt-env`: строка в `.env`
    -- действует, хотя в окружении процесса переменной нет.
    local env = helper.module('tnt.env')
    local tried = {}

    env._set_source(helper.env_world({
        files = { ['.env'] = 'TNT_TLS_LIBSSL=/из/файла/libssl.so\n' },
    }))
    env.configure()

    openssl._set_source({
        open = function(name)
            table.insert(tried, name)

            return { name = name }
        end,
    })

    local lib = openssl.library()

    env._set_source(nil)

    t.assert_equals(lib, { name = '/из/файла/libssl.so' })
    t.assert_equals(tried, { '/из/файла/libssl.so' })
end

g.test_the_system_is_the_one_the_process_runs_on = function()
    -- Без подмены род системы — тот, на котором идёт процесс: иначе
    -- на macOS искали бы имена Linux и не нашли бы ничего.
    local tried = {}

    openssl._set_source({
        getenv = function() end,

        open = function(name)
            table.insert(tried, name)
        end,
    })

    openssl.library()

    t.assert_equals(tried, helper.module('tnt.tls.library').candidates(require('jit').os, nil))
end

g.test_system_decides_where_to_look = function()
    local tried = {}

    openssl._set_source({
        system = 'OSX',

        open = function(name)
            table.insert(tried, name)

            return nil
        end,
    })

    openssl.library()

    t.assert_str_contains(tried[1], 'openssl@3', 'на macOS сначала Homebrew')
end

g.test_open_refuses_without_a_library = function()
    openssl._set_source({
        open = function()
            return nil
        end,
    })

    t.assert_str_contains(select(2, openssl.open(7, settings())), 'OpenSSL не нашлась')
end

g.test_open_sets_the_floor_of_the_protocol_and_the_mode = function()
    -- TLS 1.0 и 1.1 сняты с поддержки и сломаны; частичная запись нужна,
    -- чтобы повтор после ожидания не требовал прежних аргументов.
    local _, log = use_library()

    t.assert_not_equals(openssl.open(7, settings()), nil)
    t.assert_equals(log.ctx_ctrl_123, 0x0303)
    t.assert_equals(log.ctx_ctrl_33, 3)
end

g.test_open_binds_the_descriptor_and_sends_the_name = function()
    local _, log = use_library()

    openssl.open(11, settings())

    t.assert_equals(log.fd, 11)
    t.assert_equals(log.sni, 'mail.example.org')
    t.assert_equals(log.sni_cmd, 55, 'SSL_CTRL_SET_TLSEXT_HOSTNAME')
    t.assert_equals(log.sni_type, 0, 'TLSEXT_NAMETYPE_host_name')
end

g.test_verification_asks_openssl_to_check_the_name_itself = function()
    -- Сверять имя после рукопожатия своими руками значит однажды
    -- не сверить: шифрование к тому времени уже работает.
    local _, log = use_library()

    openssl.open(7, settings())

    t.assert_equals(log.host, 'mail.example.org')
    t.assert_equals(log.verify_mode, 1, 'SSL_VERIFY_PEER')
    t.assert_equals(log.default_roots, true)
end

g.test_own_roots_replace_the_system_ones = function()
    -- Назвавший свой удостоверяющий центр обычно как раз и хочет,
    -- чтобы никакой другой не подошёл.
    local _, log = use_library()

    openssl.open(7, settings({ ca_file = '/своё.pem', ca_path = '/корни' }))

    t.assert_equals(log.ca_file, '/своё.pem')
    t.assert_equals(log.ca_path, '/корни')
    t.assert_equals(log.default_roots, nil)
end

g.test_without_verification_nothing_is_checked = function()
    local _, log = use_library()

    openssl.open(7, settings({ verify = false }))

    t.assert_equals(log.verify_mode, nil)
    t.assert_equals(log.host, nil)
    t.assert_equals(log.default_roots, nil)

    -- Имя в SNI уходит и без проверки: без него виртуальный сервер
    -- отдаёт сертификат не тот, а шифровать надо с тем, с кем говорим.
    t.assert_equals(log.sni, 'mail.example.org')
end

g.test_open_says_when_the_context_did_not_come_out = function()
    use_library({ no_context = true, errors = { 42 } })

    local session, err = openssl.open(7, settings())

    t.assert_equals(session, nil)
    t.assert_str_contains(err, 'подготовка TLS не удалось')
    t.assert_str_contains(err, 'error:42')
end

g.test_open_says_when_the_session_did_not_come_out = function()
    use_library({ no_ssl = true })

    t.assert_str_contains(select(2, openssl.open(7, settings())), 'подготовка TLS не удалось')
end

g.test_open_says_when_the_descriptor_was_not_taken = function()
    use_library({ no_fd = true })

    t.assert_str_contains(select(2, openssl.open(7, settings())), 'привязка TLS к сокету')
end

g.test_open_says_when_the_name_was_not_taken = function()
    use_library({ no_host = true })

    t.assert_str_contains(select(2, openssl.open(7, settings())), 'проверка имени узла')
end

g.test_open_says_when_the_roots_were_not_read = function()
    use_library({ no_roots = true })

    t.assert_str_contains(
        select(2, openssl.open(7, settings({ ca_file = '/нет.pem' }))),
        'чтение доверенных корней не удалось'
    )
end

g.test_open_says_when_the_system_roots_were_not_read = function()
    use_library({ no_default_roots = true })

    t.assert_str_contains(
        select(2, openssl.open(7, settings())),
        'чтение доверенных корней системы'
    )
end

g.test_handshake_answers_with_states = function()
    use_library({ connect = { -1, -1, 1 }, error_code = 2 })

    local session = openssl.open(7, settings())

    t.assert_equals(openssl.handshake(session), outcome.WANT_READ)
    t.assert_equals(openssl.handshake(session), outcome.WANT_READ)
    t.assert_equals(openssl.handshake(session), outcome.DONE)
end

g.test_refusal_without_a_verdict_does_not_blame_the_certificate = function()
    -- Проверка сертификата прошла, отказ — другой: разбор проверки
    -- в причину не идёт, иначе человек пошёл бы чинить не то.
    use_library({ connect = { -1 }, error_code = 1, errors = { 7 }, verify_result = 0 })

    local state, err, kind = openssl.handshake(openssl.open(7, settings()))

    t.assert_equals(state, outcome.FAILED)
    t.assert_equals(err, 'рукопожатие TLS не удалось: error:7')
    t.assert_equals(kind, nil, 'сертификат принят: отказ не назван непринятым')
end

g.test_handshake_explains_a_refused_certificate = function()
    -- Номер кода в отчёте бесполезен: по нему ничего не понять,
    -- не открыв заголовки OpenSSL.
    use_library({ connect = { -1 }, error_code = 1, errors = { 168296582 }, verify_result = 18 })

    local session = openssl.open(7, settings())
    local state, err, kind = openssl.handshake(session)

    t.assert_equals(state, outcome.FAILED)
    t.assert_str_contains(err, 'сертификат не принят: self-signed certificate')
    t.assert_str_contains(err, 'error:168296582')
    -- Словом, а не только текстом: вызывающий по нему решает, повторять ли.
    t.assert_equals(kind, outcome.UNTRUSTED)
end

g.test_read_brings_back_what_came = function()
    local _, log = use_library({ read = { 'ответ сервера' } })

    local session = openssl.open(7, settings())
    local state, data = openssl.read(session)

    t.assert_equals(state, outcome.DONE)
    t.assert_equals(data, 'ответ сервера')
    t.assert_equals(log.read_size, 16 * 1024, 'читается запись TLS целиком')
end

g.test_read_counts_a_single_byte_as_data = function()
    use_library({ read = { 'x' } })

    t.assert_equals({ openssl.read(openssl.open(7, settings())) }, { outcome.DONE, 'x' })
end

g.test_read_of_nothing_is_not_data = function()
    -- Ноль от SSL_read — не пустые данные, а повод спросить у OpenSSL,
    -- что случилось: здесь это конец разговора.
    use_library({ read = { 0 }, error_code = 6 })

    t.assert_equals({ openssl.read(openssl.open(7, settings())) }, { outcome.CLOSED })
end

g.test_broken_connection_without_a_queue_is_the_end_of_the_talk = function()
    -- SSL_ERROR_SYSCALL с пустой очередью — обрыв TCP без прощания,
    -- с записью в очереди — отказ. Одной записи довольно.
    use_library({ read = { -1, -1 }, error_code = 5, errors = { 0, 9 } })

    local session = openssl.open(7, settings())

    t.assert_equals({ openssl.read(session) }, { outcome.CLOSED })

    local state, _, err = openssl.read(session)

    t.assert_equals(state, outcome.FAILED)
    t.assert_equals(err, 'чтение из TLS не удалось: error:9')
end

g.test_read_tells_the_end_of_the_talk_from_a_refusal = function()
    use_library({ read = { -1 }, error_code = 6 })

    t.assert_equals(openssl.read(openssl.open(7, settings())), outcome.CLOSED)
end

g.test_write_goes_from_the_place_where_it_stopped = function()
    -- Повтор после ожидания продолжает с того места, где встал: копии
    -- строки при этом не делается, указатель берётся внутрь неё.
    local _, log = use_library({ write = { 4 } })

    local session = openssl.open(7, settings())
    local state, written = openssl.write(session, 'EHLO node', 5)

    t.assert_equals(state, outcome.DONE)
    t.assert_equals(written, 4)
    t.assert_equals(log.written[1], 'node')
end

g.test_write_counts_a_single_byte_as_sent = function()
    use_library({ write = { 1 } })

    t.assert_equals({ openssl.write(openssl.open(7, settings()), 'EHLO', 0) }, { outcome.DONE, 1 })
end

g.test_write_of_nothing_is_not_sent = function()
    use_library({ write = { 0 }, error_code = 3 })

    t.assert_equals({ openssl.write(openssl.open(7, settings()), 'EHLO', 0) }, { outcome.WANT_WRITE })
end

g.test_write_answers_with_a_state_when_it_did_not_go = function()
    use_library({ write = { -1 }, error_code = 3 })

    t.assert_equals(openssl.write(openssl.open(7, settings()), 'что-нибудь', 0), outcome.WANT_WRITE)
end

g.test_goodbye_tells_ones_own_from_both = function()
    -- Единица — попрощались обе стороны; ноль — своё ушло, чужого нет.
    use_library({ shutdown = { 0, 1 } })

    local session = openssl.open(7, settings())

    t.assert_equals(openssl.shutdown(session), outcome.CLOSED)
    t.assert_equals(openssl.shutdown(session), outcome.DONE)
end

g.test_refused_goodbye_is_a_failure = function()
    use_library({ shutdown = { -1 }, error_code = 1, errors = { 7 } })

    t.assert_equals(openssl.shutdown(openssl.open(7, settings())), outcome.FAILED)
end

g.test_release_frees_both_and_only_once = function()
    -- Ждать сборки мусора значит держать тысячи буферов OpenSSL,
    -- которых не видит ни один счётчик Lua.
    local _, log = use_library()

    local session = openssl.open(7, settings())

    openssl.release(session)
    openssl.release(session)

    t.assert_equals(log.freed_ssl, 1)
    t.assert_equals(log.freed_ctx, 1)
end

g.test_describe_tells_the_protocol_and_the_cipher = function()
    use_library({ protocol = 'TLSv1.2', cipher = 'ECDHE-RSA-AES256-GCM-SHA384' })

    local agreed = openssl.describe(openssl.open(7, settings()))

    t.assert_equals(agreed.protocol, 'TLSv1.2')
    t.assert_equals(agreed.cipher, 'ECDHE-RSA-AES256-GCM-SHA384')
end

g.test_describe_survives_an_unnegotiated_cipher = function()
    use_library({ no_cipher = true })

    t.assert_equals(openssl.describe(openssl.open(7, settings())).cipher, nil)
end

g.test_queue_is_drained_whole = function()
    -- Хвост, оставленный в очереди, достался бы следующему вызову
    -- как его собственная ошибка.
    local lib, log = use_library({ errors = { 1, 2, 3 } })

    t.assert_equals(openssl.queue(lib), { 'error:1', 'error:2', 'error:3' })
    t.assert_equals(openssl.queue(lib), {})
    t.assert_equals(log.error_text_size, 256, 'места столько, сколько советует OpenSSL')
end

g.test_client_certificate_goes_with_its_key = function()
    -- Пустой пароль встаёт раньше ключа: ключ под паролем иначе заставил
    -- бы OpenSSL спрашивать пароль у терминала и держать весь узел.
    local _, log = use_library()

    t.assert_not_equals(
        openssl.open(7, settings({ cert_file = '/клиент.pem', key_file = '/клиент.key' })),
        nil
    )
    t.assert_equals(log.identity, { 'chain', 'password', 'key', 'check' })
    t.assert_equals(log.cert_file, '/клиент.pem')
    t.assert_equals(log.key_file, '/клиент.key')
    t.assert_equals(log.password, '')
    t.assert_equals(log.key_kind, 1, 'SSL_FILETYPE_PEM')
end

g.test_client_certificate_does_not_depend_on_verification = function()
    -- Сервер спрашивает сертификат клиента и тогда, когда мы сервер
    -- не проверяем.
    local _, log = use_library()

    openssl.open(7, settings({ verify = false, cert_file = '/клиент.pem', key_file = '/клиент.pem' }))

    t.assert_equals(log.identity, { 'chain', 'password', 'key', 'check' })
    t.assert_equals(log.verify_mode, nil)
end

g.test_without_a_certificate_nothing_is_presented = function()
    local _, log = use_library()

    openssl.open(7, settings())

    t.assert_equals(log.identity, {})
end

g.test_open_says_which_certificate_was_not_read = function()
    local _, log = use_library({ no_cert = true, errors = { 5 } })

    t.assert_equals(
        { openssl.open(7, settings({ cert_file = '/нет.pem', key_file = '/нет.key' })) },
        { nil, 'чтение сертификата клиента /нет.pem не удалось: error:5' }
    )
    t.assert_equals(log.identity, { 'chain' }, 'ключ без сертификата не читается')
end

g.test_open_says_which_key_was_not_read = function()
    local _, log = use_library({ no_key = true, errors = { 6 } })

    t.assert_equals(
        { openssl.open(7, settings({ cert_file = '/клиент.pem', key_file = '/под-паролем.key' })) },
        { nil, 'чтение ключа клиента /под-паролем.key не удалось: error:6' }
    )
    t.assert_equals(log.identity, { 'chain', 'password', 'key' })
end

g.test_open_says_when_the_key_is_not_of_the_certificate = function()
    use_library({ no_match = true, errors = { 7 } })

    t.assert_equals({ openssl.open(7, settings({ cert_file = '/клиент.pem', key_file = '/чужой.key' })) }, {
        nil,
        'сопоставление ключа /чужой.key с сертификатом /клиент.pem не удалось: error:7',
    })
end

g.test_buffered_tells_whether_openssl_holds_something_unread = function()
    use_library({ pending = 1 })
    t.assert_equals(openssl.buffered(openssl.open(7, settings())), true)

    openssl.forget()
    use_library({ pending = 0 })
    t.assert_equals(openssl.buffered(openssl.open(7, settings())), false)
end

g.test_without_verification_the_verdict_does_not_go_into_the_reason = function()
    -- Без проверки OpenSSL всё равно пишет вердикт, но отказа он
    -- не вызывал: отказ здесь — от сервера, не принявшего наш сертификат.
    use_library({ connect = { -1 }, error_code = 1, errors = { 1116 }, verify_result = 18 })

    local state, err, kind = openssl.handshake(openssl.open(7, settings({ verify = false })))

    t.assert_equals(state, outcome.FAILED)
    t.assert_equals(err, 'рукопожатие TLS не удалось: error:1116')
    t.assert_equals(kind, nil, 'и род отказа не винит сертификат сервера')
end
