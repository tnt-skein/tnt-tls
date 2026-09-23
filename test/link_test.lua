--- Тесты соединения: ожидания, сроки, накопление и освобождение.
---
--- Здесь нет ни OpenSSL, ни сервера: слой FFI подменён двойником,
--- который отвечает состояниями по листу. Так проверяются ветки,
--- которых у живого сервера не добиться, — отказ посреди записи,
--- обрыв между двумя ожиданиями, исчерпанный срок закрытия.

local fiber = require('fiber')
local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.tls.link')

---@type any
local link

---@type any
local outcome

--- Который час по мнению соединения.
---@type number
local now

--- На сколько отметка цикла событий отстаёт от настоящих часов.
---@type number
local lag

--- Сколько длится работа без уступки в проверках на настоящих часах.
local WORK = 0.02

g.before_each(function()
    now = 1000
    lag = 0
    link = helper.load('tnt.tls.link')
    outcome = helper.module('tnt.tls.outcome')

    link._set_source({
        monotonic = function()
            return now
        end,
        scheduler_now = function()
            return now - lag
        end,
    })
end)

g.after_each(function()
    link._set_source(nil)
    helper.unload()
end)

--- Настройки соединения с почтовым сервером.
---@param overrides table|nil
---@return table
local function settings(overrides)
    local chosen = {
        host = 'mail.example.org',
        port = 993,
        timeout = 5,
        verify = true,
    }

    for name, value in pairs(overrides or {}) do
        chosen[name] = value
    end

    return chosen
end

--- Готовое соединение поверх двойников.
---@param plan table|nil Лист ответов слоя FFI
---@param state table|nil Состояние двойника сокета
---@return any established
---@return table log
---@return table socket_state
local function established(plan, state)
    local socket, socket_state = helper.socket(state)
    local backend, log = helper.backend(plan)

    return link.new(socket, { alive = true }, backend, settings()), log, socket_state
end

g.test_handshake_passes_at_once = function()
    local socket = helper.socket()
    local backend, log = helper.backend({ handshake = { { outcome.DONE } } })

    local ready = link.establish(socket, settings(), backend)

    t.assert_not_equals(ready, nil)
    t.assert_equals(log.opened, 1)
    t.assert_equals(log.fd, 7, 'слою отдан дескриптор сокета')
    t.assert_equals(log.released, 0)
end

g.test_handshake_waits_for_the_descriptor_instead_of_spinning = function()
    -- Крутить цикл на «повтори позже» значит занять поток целиком.
    local socket, state = helper.socket()
    local backend = helper.backend({
        handshake = { { outcome.WANT_READ }, { outcome.WANT_WRITE }, { outcome.DONE } },
    })

    t.assert_not_equals(link.establish(socket, settings(), backend), nil)
    t.assert_equals(#state.waits, 2)
    t.assert_equals(state.waits[1].kind, 'readable')
    t.assert_equals(state.waits[2].kind, 'writable')
end

g.test_handshake_asks_to_wait_only_the_time_that_is_left = function()
    local socket, state = helper.socket()
    local backend = helper.backend({ handshake = { { outcome.WANT_READ }, { outcome.DONE } } })

    now = now + 3

    link.establish(socket, settings(), backend)

    t.assert_almost_equals(state.waits[1].timeout, 5, 1e-9)
end

g.test_deadline_is_marked_by_the_clock_and_the_wait_counts_from_the_loop_stamp = function()
    -- Отметка цикла событий отстаёт на три секунды работы без уступки.
    -- Срок отмечен настоящими часами в миг вызова, а ожидание отсчитает
    -- остаток от отстающей отметки: чтобы кончиться ровно в срок, ему
    -- нужны все восемь секунд. Срок по отметке цикла съела бы работа
    -- до вызова, остаток по настоящим часам кончился бы на три раньше.
    local socket, state = helper.socket()
    local backend = helper.backend({ handshake = { { outcome.WANT_READ }, { outcome.DONE } } })

    lag = 3

    link.establish(socket, settings(), backend)

    t.assert_equals(state.waits[1].timeout, 8)
end

g.test_handshake_after_work_without_yielding_keeps_the_whole_timeout = function()
    -- Часы не подменены. Ни работа вызывающего перед рукопожатием,
    -- ни OpenSSL, считающий ключи, отметку цикла событий не двигают,
    -- а ожидание готовности отсчитывает остаток от неё. Чтобы оно кончилось
    -- в срок, отмеченный в миг вызова, остаток обязан покрыть и пять секунд,
    -- и работу перед вызовом; по настоящим часам он вышел бы короче пяти
    -- на время счёта ключей.
    link._set_source(nil)

    local socket, state = helper.socket()
    local backend = helper.backend({ handshake = { { outcome.WANT_READ }, { outcome.DONE } } })
    local scripted = backend.handshake

    backend.handshake = function(session)
        helper.work_without_yielding(WORK)

        return scripted(session)
    end

    fiber.yield()
    helper.work_without_yielding(WORK)
    link.establish(socket, settings(), backend)

    t.assert_ge(state.waits[1].timeout, 5 + WORK)
end

g.test_handshake_refusal_frees_what_it_had = function()
    -- SSL и SSL_CTX не видит ни один счётчик Lua: утёкшие, они
    -- не найдутся никогда.
    local socket = helper.socket()
    local backend, log =
        helper.backend({ handshake = { { outcome.FAILED, 'сертификат не принят' } } })

    local ready, err, kind = link.establish(socket, settings(), backend)

    t.assert_equals(ready, nil)
    t.assert_equals(err, 'сертификат не принят')
    t.assert_equals(kind, nil, 'слой рода не назвал — и здесь его нет')
    t.assert_equals(log.released, 1)
end

g.test_handshake_refusal_keeps_the_kind_the_layer_named = function()
    -- Непринятый сертификат время не лечит, и вызывающему нужно слово,
    -- а не текст: по слову он откажет сразу, а не повторит до конца срока.
    local socket = helper.socket()
    local backend, log = helper.backend({
        handshake = {
            { outcome.WANT_READ },
            { outcome.FAILED, 'сертификат не принят: self-signed certificate', outcome.UNTRUSTED },
        },
    })

    t.assert_equals(
        { link.establish(socket, settings(), backend) },
        { nil, 'сертификат не принят: self-signed certificate', 'untrusted' }
    )
    t.assert_equals(log.released, 1)
end

g.test_handshake_broken_by_the_other_side_says_so = function()
    local socket = helper.socket()
    local backend, log = helper.backend({ handshake = { { outcome.CLOSED } } })

    local ready, err = link.establish(socket, settings(), backend)

    t.assert_equals(ready, nil)
    t.assert_str_contains(err, 'оборвано другой стороной')
    t.assert_equals(log.released, 1)
end

g.test_handshake_gives_up_on_the_deadline = function()
    -- Истёкший срок — отказ, а не вечное ожидание.
    local socket = helper.socket({ ready = false })
    local backend, log = helper.backend({ handshake = { { outcome.WANT_READ } } })

    local ready, err = link.establish(socket, settings(), backend)

    t.assert_equals(ready, nil)
    t.assert_str_contains(err, 'не уложилось в 5 с')
    t.assert_equals(log.released, 1)
end

g.test_a_deadline_that_has_passed_is_not_offered_to_the_socket = function()
    -- Отрицательный остаток срока сокет понимает по-своему: «уже поздно»
    -- превратилось бы в «жди сколько угодно».
    local socket, state = helper.socket()

    state.tick = function()
        now = now + 10
    end

    local backend, log = helper.backend({
        handshake = { { outcome.WANT_READ }, { outcome.WANT_READ } },
    })

    local ready, err = link.establish(socket, settings(), backend)

    t.assert_equals(ready, nil)
    t.assert_str_contains(err, 'не уложилось в 5 с')
    t.assert_equals(#state.waits, 1, 'второй раз ждать уже поздно')
    t.assert_equals(log.released, 1)
end

g.test_a_deadline_reached_to_the_instant_is_not_offered_to_the_socket = function()
    -- Срок, вышедший ровно в этот миг, — тоже вышедший: ноль, отданный
    -- сокету, стал бы ещё одним вопросом о готовности уже за сроком,
    -- и рукопожатие пошло бы дальше.
    local socket, state = helper.socket()
    local backend, log = helper.backend({ handshake = { { outcome.WANT_READ } } })
    local scripted = backend.handshake

    backend.handshake = function(session)
        now = now + 5

        return scripted(session)
    end

    local ready, err = link.establish(socket, settings(), backend)

    t.assert_equals(ready, nil)
    t.assert_str_contains(err, 'не уложилось в 5 с')
    t.assert_equals(#state.waits, 0)
    t.assert_equals(log.released, 1)
end

g.test_handshake_needs_a_socket_with_a_descriptor = function()
    local backend, log = helper.backend()

    local ready, err = link.establish({}, settings(), backend)

    t.assert_equals(ready, nil)
    t.assert_str_contains(err, 'у сокета нет дескриптора')
    t.assert_equals(log.opened, 0, 'до слоя дело не дошло')
end

g.test_handshake_refuses_a_closed_descriptor = function()
    local socket = helper.socket({ fd_value = -1 })

    t.assert_str_contains(
        select(2, link.establish(socket, settings(), helper.backend())),
        'нет дескриптора'
    )
end

g.test_descriptor_zero_is_a_descriptor = function()
    -- Нулевой дескриптор законен: процесс, закрывший стандартный ввод,
    -- получит под сокет именно его.
    local socket = helper.socket({ fd_value = 0 })
    local backend, log = helper.backend()

    t.assert_not_equals(link.establish(socket, settings(), backend), nil)
    t.assert_equals(log.fd, 0)
end

g.test_descriptor_that_is_not_a_number_is_refused = function()
    local socket = helper.socket()

    socket.fd = function()
        return 'семь'
    end

    local backend, log = helper.backend()
    local ready, err = link.establish(socket, settings(), backend)

    t.assert_equals(ready, nil)
    t.assert_str_contains(err, 'у сокета нет дескриптора')
    t.assert_equals(log.opened, 0)
end

g.test_handshake_passes_the_refusal_of_the_ffi_layer = function()
    local socket = helper.socket()
    local backend = helper.backend({ open_error = 'OpenSSL не нашлась' })

    t.assert_equals(select(2, link.establish(socket, settings(), backend)), 'OpenSSL не нашлась')
end

g.test_read_by_delimiter_gathers_pieces = function()
    -- Одно чтение приносит не строку, а сколько пришло: шифрованный
    -- поток не совпадает ни со строками протокола, ни с запрошенным.
    local ready = established({
        read = { { outcome.DONE, '250 ' }, { outcome.DONE, 'OK\r\n250 ещё\r\n' } },
    })

    t.assert_equals(ready:read({ delimiter = '\r\n' }), '250 OK\r\n')
    t.assert_equals(
        ready:read({ delimiter = '\r\n' }),
        '250 ещё\r\n',
        'остаток отдан без похода в сеть'
    )
end

g.test_read_by_size_gives_exactly_what_was_asked = function()
    local ready = established({ read = { { outcome.DONE, 'письмо целиком' } } })

    -- Размер считается байтами: тело письма приходит длиной в байтах.
    t.assert_equals(ready:read({ chunk = 6 }), 'пис')
end

g.test_read_waits_for_the_descriptor = function()
    local ready, _, state = established({
        read = { { outcome.WANT_READ }, { outcome.WANT_WRITE }, { outcome.DONE, 'ответ\n' } },
    })

    t.assert_equals(ready:read({ delimiter = '\n' }), 'ответ\n')
    t.assert_equals(state.waits[1].kind, 'readable')
    t.assert_equals(
        state.waits[2].kind,
        'writable',
        'перевыбор ключей просит записи посреди чтения'
    )
end

g.test_read_ends_with_the_tail_and_then_with_emptiness = function()
    -- Так отличается «сервер закончил» от «сервер молчит», и
    -- построчный протокол видит эту разницу сам.
    local ready = established({ read = { { outcome.DONE, 'хвост' }, { outcome.CLOSED } } })

    t.assert_equals(ready:read({ delimiter = '\r\n' }), 'хвост')
    t.assert_equals(ready:read({ delimiter = '\r\n' }), '')
end

g.test_read_respects_its_own_deadline = function()
    local ready, _, state = established({ read = { { outcome.WANT_READ } } })

    state.ready = false

    local line, err = ready:read({ delimiter = '\r\n' }, 2)

    t.assert_equals(line, nil)
    t.assert_str_contains(err, 'не ответил за 2 с')
end

g.test_read_passes_the_refusal_of_the_ffi_layer = function()
    local ready = established({
        read = { { outcome.FAILED, nil, 'чтение из TLS не удалось: разбитая запись' } },
    })

    t.assert_str_contains(select(2, ready:read({ delimiter = '\r\n' })), 'разбитая запись')
end

g.test_read_demands_to_know_how_much = function()
    local ready = established()

    t.assert_str_contains(select(2, ready:read({})), 'не сказано, сколько читать')
end

g.test_read_does_not_gather_a_line_without_end = function()
    -- Сервер, который не шлёт разделитель, съел бы память узла целиком.
    local ready = established({
        read = { { outcome.DONE, ('я'):rep(10) }, { outcome.DONE, ('я'):rep(10) } },
    })

    local line, err = ready:read({ delimiter = '\r\n', limit = 12 })

    t.assert_equals(line, nil)
    t.assert_str_contains(err, 'разделитель так и не пришёл')
end

g.test_write_goes_out_whole = function()
    -- Половина команды протокола — это сорванный разговор, а не
    -- частичный успех.
    local ready, log = established({
        write = { { outcome.DONE, 4 }, { outcome.DONE, 5 } },
    })

    t.assert_equals(ready:write('EHLO node'), true)
    t.assert_equals(log.writes[1].sent, 0)
    t.assert_equals(
        log.writes[2].sent,
        4,
        'второй заход продолжает с того места, где встал первый'
    )
end

g.test_write_waits_for_room = function()
    local ready, _, state = established({
        write = { { outcome.WANT_WRITE }, { outcome.WANT_READ }, { outcome.DONE, 6 } },
    })

    t.assert_equals(ready:write('три'), true)
    t.assert_equals(state.waits[1].kind, 'writable')
    t.assert_equals(state.waits[2].kind, 'readable')
end

g.test_write_respects_its_own_deadline = function()
    local ready, _, state = established({ write = { { outcome.WANT_WRITE } } })

    state.ready = false

    local written, err = ready:write('ещё', 3)

    t.assert_equals(written, false)
    t.assert_str_contains(err, 'не принял запись за 3 с')
    t.assert_almost_equals(state.waits[1].timeout, 3, 1e-9)
end

g.test_write_into_a_closed_talk_is_a_refusal = function()
    local ready = established({ write = { { outcome.CLOSED } } })

    local written, err = ready:write('поздно')

    t.assert_equals(written, false)
    t.assert_str_contains(err, 'закрыл соединение посреди записи')
end

g.test_write_passes_the_refusal_of_the_ffi_layer = function()
    local ready = established({
        write = { { outcome.FAILED, nil, 'запись в TLS не удалась: разбитая запись' } },
    })

    local written, err = ready:write('что-нибудь')

    t.assert_equals(written, false)
    t.assert_str_contains(err, 'разбитая запись')
end

g.test_empty_write_never_reaches_openssl = function()
    -- SSL_write нулевой длины не определён, и разные версии понимают
    -- его по-разному.
    local ready, log = established({ write = {} })

    t.assert_equals(ready:write(''), true)
    t.assert_equals(#log.writes, 0)
end

g.test_write_takes_a_string_and_says_so = function()
    local written, err = established():write({ 'не строка' })

    t.assert_equals(written, false)
    t.assert_str_contains(err, 'писать можно строку')
end

g.test_goodbye_is_two_sided = function()
    -- Первый вызов шлёт своё прощание, второй читает чужое.
    local ready, log, state = established({ shutdown = { { outcome.CLOSED }, { outcome.DONE } } })

    ready:close()

    t.assert_equals(log.released, 1)
    t.assert_equals(state.closed, true, 'сокет закрыт вместе с разговором')
end

g.test_goodbye_does_not_wait_forever = function()
    -- Сервер вправе закрыть сокет сразу после своего прощания.
    local ready, log = established({
        shutdown = { { outcome.WANT_READ } },
    }, { ready = false })

    ready:close()

    t.assert_equals(log.released, 1)
end

g.test_goodbye_waits_the_shorter_of_the_two_terms = function()
    -- Держать файбер на закрытии дольше, чем на разговоре, незачем.
    local ready, _, state = established({ shutdown = { { outcome.WANT_WRITE }, { outcome.DONE } } })

    ready:close()

    t.assert_almost_equals(state.waits[1].timeout, 1, 1e-9)
    t.assert_equals(state.waits[1].kind, 'writable')
end

g.test_goodbye_that_wants_to_read_waits_for_reading = function()
    local ready, _, state = established({ shutdown = { { outcome.WANT_READ }, { outcome.DONE } } })

    ready:close()

    t.assert_equals(state.waits[1].kind, 'readable')
end

g.test_goodbye_takes_four_rounds_and_no_more = function()
    -- Два вызова SSL_shutdown — само прощание; ожидания готовности между
    -- ними добавляют обороты, и предел их — ровно четыре.
    local ready, log, state = established({
        shutdown = {
            { outcome.WANT_READ },
            { outcome.WANT_READ },
            { outcome.WANT_READ },
            { outcome.WANT_READ },
        },
    })

    ready:close()

    t.assert_equals(#state.waits, 4)
    t.assert_equals(log.released, 1)
end

g.test_refused_goodbye_still_frees = function()
    local ready, log = established({ shutdown = { { outcome.FAILED } } })

    ready:close()

    t.assert_equals(log.released, 1)
end

g.test_closing_twice_frees_once = function()
    local ready, log = established({ shutdown = { { outcome.DONE } } })

    ready:close()
    ready:close()

    t.assert_equals(log.released, 1)
end

g.test_a_closed_talk_neither_reads_nor_writes = function()
    local ready = established({ shutdown = { { outcome.DONE } } })

    ready:close()

    t.assert_str_contains(select(2, ready:read({ chunk = 1 })), 'соединение закрыто')

    local written, err = ready:write('поздно')

    t.assert_equals(written, false)
    t.assert_str_contains(err, 'соединение закрыто')
end

--- Прощание со стороной, вечно отвечающей «своё ушло, чужого нет».
---
--- Каждый ответ такой стороны занимает время: часы уходят вперёд на шаг.
---@param step number На сколько секунд двигается время за один ответ
---@param also (fun())|nil Что ещё случается за один ответ
---@return integer calls Сколько раз прощание спросило другую сторону
---@return table log
local function endless_goodbye(step, also)
    local backend, log = helper.backend({
        shutdown = { { outcome.CLOSED }, { outcome.CLOSED }, { outcome.CLOSED }, { outcome.CLOSED } },
    })
    local scripted = backend.shutdown
    local calls = 0

    backend.shutdown = function(session)
        calls = calls + 1
        now = now + step

        if also ~= nil then
            also()
        end

        return scripted(session)
    end

    link.new(helper.socket(), { alive = true }, backend, settings()):close()

    return calls, log
end

g.test_endless_goodbye_stops_by_the_deadline = function()
    -- Сторона, вечно отвечающая «своё ушло, чужого нет», не должна
    -- держать файбер.
    local calls, log = endless_goodbye(10)

    t.assert_equals(calls, 1)
    t.assert_equals(log.released, 1)
end

g.test_goodbye_stops_the_moment_its_term_is_up = function()
    local calls = endless_goodbye(1)

    t.assert_equals(calls, 1)
end

g.test_goodbye_asks_the_clock_and_not_the_loop_stamp_whether_the_term_is_up = function()
    -- Срок — миг на настоящих часах, и вышел ли он, решают они же. Отметка
    -- цикла стоит, пока прощание не уступает, и по ней срок не вышел бы
    -- никогда: прощание ходило бы до предела оборотов.
    local calls = endless_goodbye(1, function()
        lag = lag + 1
    end)

    t.assert_equals(calls, 1)
end

g.test_peer_tells_what_was_agreed_and_survives_closing = function()
    -- Шифр и версия нужны в журнале как раз тогда, когда соединение
    -- уже закрыто.
    local ready, log = established({
        shutdown = { { outcome.DONE } },
        describe = { protocol = 'TLSv1.2', cipher = 'ECDHE-RSA-AES256-GCM-SHA384' },
    })

    ready:close()

    local peer = ready:peer()

    t.assert_equals(peer.host, 'mail.example.org')
    t.assert_equals(peer.port, 993)
    t.assert_equals(peer.protocol, 'TLSv1.2')
    t.assert_equals(peer.cipher, 'ECDHE-RSA-AES256-GCM-SHA384')
    t.assert_equals(
        log.describes,
        1,
        'у освобождённой сессии спрашивать уже некого'
    )
end

g.test_port_is_asked_of_the_socket_when_it_was_not_given = function()
    -- У STARTTLS порта в опциях нет: сокет открыл вызывающий.
    local socket = helper.socket({ peer_info = { host = '10.0.0.7', port = 587 } })

    t.assert_equals(link.port_of(socket, nil), 587)
    t.assert_equals(
        link.port_of(socket, 465),
        465,
        'заданный порт важнее подсмотренного'
    )
end

g.test_answer_about_the_other_side_that_is_not_a_table_leaves_the_port_unknown = function()
    t.assert_equals(link.port_of(helper.socket({ peer_info = false }), nil), nil)
end

g.test_silent_socket_leaves_the_port_unknown = function()
    -- Закрытый сокет отвечает на вопрос о другой стороне ошибкой,
    -- и ронять ею того, кто просто пишет в журнал, незачем.
    t.assert_equals(link.port_of(helper.socket(), nil), nil)
end

g.test_a_socket_closed_by_a_neighbour_does_not_bring_down_the_reader = function()
    local ready = established({ read = { { outcome.WANT_READ } } }, { raises = true })

    t.assert_str_contains(select(2, ready:read({ chunk = 1 }, 4)), 'не ответил за 4 с')
end

g.test_an_untouched_connection_is_idle = function()
    -- В сокет только заглядывают: прочитанную запись TLS назад в поток
    -- не вернуть, и живое соединение после такой проверки было бы испорчено.
    local ready, _, state = established()

    t.assert_equals(ready:idle(), true)
    t.assert_equals(state.peeks, { { size = 1, flags = 'MSG_PEEK' } })
end

g.test_anything_in_the_socket_means_not_idle = function()
    -- Прощание TLS от сервера, закрывшего соединение, и любая другая
    -- запись — всё равно «не свободно»: лишнее соединение дешевле отказа
    -- на запросе, который уже ушёл.
    local ready = established(nil, { peeked = '\21' })

    t.assert_equals(ready:idle(), false)
end

g.test_end_of_stream_in_the_socket_means_not_idle = function()
    local ready = established(nil, { peeked = '' })

    t.assert_equals(ready:idle(), false)
end

g.test_a_socket_error_means_not_idle = function()
    -- Пусто, но не потому, что читать нечего: сокет сброшен.
    local ready = established(nil, { peek_errno = require('errno').ECONNRESET })

    t.assert_equals(ready:idle(), false)
end

g.test_a_socket_closed_by_a_neighbour_means_not_idle = function()
    local ready = established(nil, { peek_raises = true })

    t.assert_equals(ready:idle(), false)
end

g.test_what_openssl_holds_means_not_idle_without_looking_into_the_socket = function()
    -- Записи, уже взятые из сокета, видны только OpenSSL: сокет о них
    -- не скажет.
    local ready, _, state = established({ buffered = true })

    t.assert_equals(ready:idle(), false)
    t.assert_equals(state.peeks, {})
end

g.test_what_was_read_but_not_given_away_means_not_idle = function()
    local ready, _, state = established({ read = { { outcome.DONE, 'один\r\nдва\r\n' } } })

    t.assert_equals(ready:read({ delimiter = '\r\n' }), 'один\r\n')
    t.assert_equals(ready:idle(), false)
    t.assert_equals(state.peeks, {})
end

g.test_a_finished_talk_is_not_idle = function()
    local ready, _, state = established({ read = { { outcome.CLOSED } } })

    t.assert_equals(ready:read({ chunk = 1 }), '')
    t.assert_equals(ready:idle(), false)
    t.assert_equals(state.peeks, {})
end

g.test_a_closed_connection_is_not_idle = function()
    local ready, _, state = established()

    ready:close()

    t.assert_equals(ready:idle(), false)
    t.assert_equals(state.peeks, {})
end
