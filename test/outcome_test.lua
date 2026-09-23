--- Тесты разбора ответов OpenSSL: что значит код и как сказать о нём.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.tls.outcome')

---@type any
local outcome

g.before_each(function()
    outcome = helper.load('tnt.tls.outcome')
end)

g.after_each(function()
    helper.unload()
end)

g.test_zero_is_success = function()
    t.assert_equals(outcome.of(0), outcome.DONE)
end

g.test_waiting_codes_are_not_failures = function()
    -- Перепутать их с отказом значит рвать исправные соединения
    -- на ровном месте.
    t.assert_equals(outcome.of(2), outcome.WANT_READ)
    t.assert_equals(outcome.of(3), outcome.WANT_WRITE)
end

g.test_zero_return_is_the_end_of_the_talk = function()
    t.assert_equals(outcome.of(6), outcome.CLOSED)
end

g.test_protocol_error_is_a_failure = function()
    t.assert_equals(outcome.of(1, true), outcome.FAILED)
    t.assert_equals(outcome.of(4), outcome.FAILED, 'незнакомый код считается отказом')
end

g.test_syscall_without_queue_is_a_silent_goodbye = function()
    -- Почти все почтовые серверы закрывают сокет, не прислав close_notify.
    -- Строгость превратила бы каждую удачную отправку в отказ.
    t.assert_equals(outcome.of(5), outcome.CLOSED)
    t.assert_equals(outcome.of(5, false), outcome.CLOSED)
end

g.test_syscall_with_queue_is_a_failure = function()
    -- Записи в очереди означают, что OpenSSL есть что сказать: это
    -- не тихий конец разговора.
    t.assert_equals(outcome.of(5, true), outcome.FAILED)
end

g.test_reason_puts_the_verdict_first = function()
    -- Первым идёт то, что объясняет отказ без OpenSSL под рукой.
    local reason = outcome.reason('рукопожатие TLS', 1, { 'error:0A000086:...' }, 'self-signed certificate')

    t.assert_str_contains(reason, 'рукопожатие TLS не удалось')
    t.assert_str_contains(reason, 'сертификат не принят: self-signed certificate')
    t.assert_str_contains(reason, 'error:0A000086')
    t.assert_lt(reason:find('сертификат', 1, true), reason:find('error:', 1, true))
end

g.test_reason_keeps_the_whole_queue = function()
    -- Объясняет отказ обычно первая запись, а не последняя.
    local reason = outcome.reason('чтение из TLS', 1, { 'первая', 'вторая' })

    t.assert_str_contains(reason, 'первая')
    t.assert_str_contains(reason, 'вторая')
end

g.test_reason_names_the_code_when_there_is_nothing_else = function()
    -- Номер кода бесполезен, а «что-то пошло не так» бесполезно вдвойне.
    t.assert_str_contains(outcome.reason('запись в TLS', 5, {}), 'SSL_ERROR_SYSCALL')
    t.assert_str_contains(outcome.reason('запись в TLS', 5, nil), 'SSL_ERROR_SYSCALL')
    t.assert_str_contains(outcome.reason('запись в TLS', 77, {}), 'код 77')
    t.assert_str_contains(outcome.reason('запись в TLS', nil, {}), 'код nil')
end

g.test_reason_ignores_an_empty_verdict = function()
    t.assert_not_str_contains(
        outcome.reason('закрытие TLS', 1, { 'текст' }, ''),
        'сертификат не принят'
    )
end

g.test_code_is_named_when_there_is_nothing_else_to_tell = function()
    -- Ни очереди ошибок, ни разбора проверки: имя кода — единственное,
    -- что остаётся, и по нему отказ ищут в документации OpenSSL.
    t.assert_str_contains(outcome.reason('рукопожатие TLS', 1, {}, nil), 'SSL_ERROR_SSL')
    t.assert_str_contains(outcome.reason('чтение из TLS', 4, {}, nil), 'SSL_ERROR_WANT_X509_LOOKUP')
    t.assert_str_contains(outcome.reason('запись в TLS', 5, {}, nil), 'SSL_ERROR_SYSCALL')
end

g.test_unknown_code_is_shown_as_it_came = function()
    -- Незнакомый код всё равно надо показать: по числу его найдут
    -- в заголовках, а «что-то пошло не так» не найдут нигде.
    t.assert_str_contains(outcome.reason('рукопожатие TLS', 42, {}, nil), '42')
end
