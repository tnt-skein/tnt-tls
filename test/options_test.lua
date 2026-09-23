--- Тесты разбора опций: умолчания строгие, негодное отсекается до сокета.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.tls.options')

---@type any
local options

g.before_each(function()
    options = helper.load('tnt.tls.options')
end)

g.after_each(function()
    helper.unload()
end)

g.test_verification_is_on_unless_switched_off_by_the_word_false = function()
    -- Забывший про verify обязан получить проверку, а не шифрование
    -- без защиты от подмены: оно даёт ложное спокойствие.
    t.assert_equals(options.normalize({ host = 'a', port = 1 }, true).verify, true)
    t.assert_equals(options.normalize({ host = 'a', port = 1, verify = nil }, true).verify, true)
    t.assert_equals(options.normalize({ host = 'a', port = 1, verify = 'false' }, true).verify, true)
    t.assert_equals(options.normalize({ host = 'a', port = 1, verify = false }, true).verify, false)
end

g.test_host_is_required = function()
    t.assert_str_contains(select(2, options.normalize({ port = 1 }, true)), 'нет host')
    t.assert_str_contains(select(2, options.normalize({ host = '', port = 1 }, true)), 'нет host')
    t.assert_str_contains(select(2, options.normalize({ host = 17, port = 1 }, true)), 'нет host')
end

g.test_options_themselves_are_required = function()
    t.assert_str_contains(select(2, options.normalize(nil, true)), 'опции не переданы')
    t.assert_str_contains(select(2, options.normalize('smtp.example.org', true)), 'опции не переданы')
end

g.test_port_is_required_for_a_fresh_connection = function()
    t.assert_str_contains(select(2, options.normalize({ host = 'a' }, true)), 'от 1 до 65535')
    t.assert_str_contains(select(2, options.normalize({ host = 'a', port = 0 }, true)), 'от 1 до 65535')
    t.assert_str_contains(select(2, options.normalize({ host = 'a', port = 70000 }, true)), 'от 1 до 65535')
    t.assert_str_contains(select(2, options.normalize({ host = 'a', port = 4.5 }, true)), 'от 1 до 65535')
end

g.test_starttls_needs_no_port = function()
    -- Сокет уже открыт: порт знает тот, кто его открыл.
    local settings = options.normalize({ host = 'smtp.example.org' }, false)

    t.assert_equals(settings.port, nil)
    t.assert_equals(settings.host, 'smtp.example.org')
end

g.test_starttls_still_checks_a_given_port = function()
    t.assert_str_contains(select(2, options.normalize({ host = 'a', port = -1 }, false)), 'от 1 до 65535')
    t.assert_equals(options.normalize({ host = 'a', port = 587 }, false).port, 587)
end

g.test_timeout_defaults_and_must_be_positive = function()
    -- Нулевой срок — это не «ждать вечно», а «не ждать вовсе»: на нём
    -- не проходит ни одно рукопожатие.
    t.assert_equals(options.normalize({ host = 'a', port = 1 }, true).timeout, options.DEFAULT_TIMEOUT)
    t.assert_equals(options.normalize({ host = 'a', port = 1, timeout = 0.5 }, true).timeout, 0.5)
    t.assert_str_contains(
        select(2, options.normalize({ host = 'a', port = 1, timeout = 0 }, true)),
        'положительным'
    )
    t.assert_str_contains(
        select(2, options.normalize({ host = 'a', port = 1, timeout = -3 }, true)),
        'положительным'
    )
    t.assert_str_contains(
        select(2, options.normalize({ host = 'a', port = 1, timeout = 'скоро' }, true)),
        'положительным'
    )
end

g.test_roots_are_carried_as_given = function()
    local settings =
        options.normalize({ host = 'a', port = 1, ca_file = '/своё.pem', ca_path = '/корни' }, true)

    t.assert_equals(settings.ca_file, '/своё.pem')
    t.assert_equals(settings.ca_path, '/корни')
end

g.test_roots_and_sni_must_be_strings = function()
    -- Не строка дошла бы до OpenSSL исключением FFI посреди настройки
    -- соединения, а сокет, открытый connect, остался бы незакрытым.
    t.assert_equals(
        select(2, options.normalize({ host = 'a', port = 1, ca_file = 123 }, true)),
        'ca_file должен быть строкой, а не number'
    )
    t.assert_equals(
        select(2, options.normalize({ host = 'a', ca_path = {} }, false)),
        'ca_path должен быть строкой, а не table'
    )
    t.assert_equals(
        select(2, options.normalize({ host = 'a', port = 1, sni = false }, true)),
        'sni должен быть строкой, а не boolean'
    )
end

g.test_sni_defaults_to_the_host = function()
    -- Виртуальных почтовых серверов на одном адресе столько же, сколько
    -- виртуальных сайтов: без SNI такой сервер отдаёт сертификат не тот.
    t.assert_equals(options.normalize({ host = 'mail.example.org', port = 993 }, true).sni, 'mail.example.org')
end

g.test_sni_can_be_said_apart_from_the_host = function()
    local settings = options.normalize({ host = '10.0.0.7', port = 993, sni = 'mail.example.org' }, true)

    t.assert_equals(settings.sni, 'mail.example.org')
end

g.test_numeric_address_gets_no_sni = function()
    -- Слать адрес в SNI запрещено RFC 6066, и некоторые серверы
    -- обрывают на этом рукопожатие.
    t.assert_equals(options.normalize({ host = '192.168.1.10', port = 993 }, true).sni, nil)
    t.assert_equals(options.normalize({ host = '::1', port = 993 }, true).sni, nil)
    t.assert_equals(options.normalize({ host = 'a', port = 1, sni = '127.0.0.1' }, true).sni, nil)
    -- Пустое имя — это «не слать SNI вовсе», а не «взять по умолчанию».
    t.assert_equals(options.normalize({ host = 'a', port = 1, sni = '' }, true).sni, nil)
    t.assert_equals(options.server_name('a', 17), nil)
end

g.test_address_is_told_from_a_name = function()
    t.assert_equals(options.looks_like_address('127.0.0.1'), true)
    t.assert_equals(options.looks_like_address('fe80::1'), true)
    t.assert_equals(options.looks_like_address('mail.example.org'), false)
    t.assert_equals(options.looks_like_address('10.0.0.1.example.org'), false)
end

g.test_broken_address_is_not_an_address = function()
    -- Числовой адрес узнаётся целиком, а не по общему виду: у «192.168.0.»
    -- и «.168.0.1» в SNI имя слать можно и нужно, потому что это имена,
    -- а не адреса, — пусть и негодные.
    for _, host in ipairs({ '192.168.0.', '.168.0.1', '192..0.1', '192.168..1' }) do
        t.assert_equals(options.looks_like_address(host), false, host)
    end

    t.assert_equals(options.looks_like_address('192.168.0.1'), true)
end

g.test_colon_anywhere_means_a_numeric_address = function()
    -- Двоеточие бывает только в IPv6, и оно значимо с первого знака:
    -- «::1» — это адрес обратной петли, а не имя узла.
    t.assert_equals(options.looks_like_address(':'), true)
    t.assert_equals(options.looks_like_address('::1'), true)
    t.assert_equals(options.looks_like_address('example.org'), false)
end

g.test_highest_port_is_a_port = function()
    -- Граница сверху включительно: 65535 — настоящий порт, и сервер
    -- на нём стоит ровно так же, как на любом другом.
    local settings, err = options.normalize({ host = 'example.org', port = 65535 }, true)

    t.assert_equals(err, nil)
    t.assert_equals(settings.port, 65535)

    local refused, why = options.normalize({ host = 'example.org', port = 65536 }, true)

    t.assert_equals(refused, nil)
    t.assert_str_contains(why, '65535')
end

g.test_client_certificate_and_key_are_carried_as_given = function()
    local settings = options.normalize(
        { host = 'a', port = 1, cert_file = '/клиент.pem', key_file = '/клиент.key' },
        true
    )

    t.assert_equals({ settings.cert_file, settings.key_file }, { '/клиент.pem', '/клиент.key' })
end

g.test_key_is_read_from_the_certificate_file_unless_named = function()
    -- Сертификат и ключ часто лежат одним файлом PEM: называть его
    -- дважды незачем.
    local settings = options.normalize({ host = 'a', port = 1, cert_file = '/клиент.pem' }, true)

    t.assert_equals({ settings.cert_file, settings.key_file }, { '/клиент.pem', '/клиент.pem' })
end

g.test_no_certificate_means_no_key = function()
    local settings = options.normalize({ host = 'a', port = 1 }, true)

    t.assert_equals({ settings.cert_file, settings.key_file }, { nil, nil })
end

g.test_key_without_certificate_is_refused = function()
    -- Ключ без сертификата предъявить нечем: соединение ушло бы без
    -- сертификата, и сервер отказал бы после рукопожатия, ни словом
    -- не назвав ключ.
    local settings, err = options.normalize({ host = 'a', key_file = '/клиент.key' }, false)

    t.assert_equals(settings, nil)
    t.assert_equals(
        err,
        'key_file без cert_file: ключ предъявляется только вместе с сертификатом'
    )
end

g.test_certificate_and_key_must_be_strings = function()
    t.assert_equals(
        select(2, options.normalize({ host = 'a', port = 1, cert_file = 7 }, true)),
        'cert_file должен быть строкой, а не number'
    )
    t.assert_equals(
        select(2, options.normalize({ host = 'a', cert_file = '/c.pem', key_file = {} }, false)),
        'key_file должен быть строкой, а не table'
    )
end
