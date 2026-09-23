--- Тесты накопителя: выдача по разделителю, по размеру и предел роста.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.tls.buffer')

---@type any
local buffer

g.before_each(function()
    buffer = helper.load('tnt.tls.buffer')
end)

g.after_each(function()
    helper.unload()
end)

g.test_delimiter_is_given_back_with_the_line = function()
    -- Так делает socket:read: тот, кто снимает разделитель сам, не должен
    -- гадать, был он или строка кончилась обрывом связи.
    local request = buffer.request({ delimiter = '\r\n' })
    local piece, rest = buffer.take('250 OK\r\n354 дальше\r\n', request)

    t.assert_equals(piece, '250 OK\r\n')
    t.assert_equals(rest, '354 дальше\r\n')
end

g.test_incomplete_line_waits = function()
    local piece, rest = buffer.take('250 O', buffer.request({ delimiter = '\r\n' }))

    t.assert_equals(piece, nil)
    t.assert_equals(rest, '250 O', 'накопленное не теряется')
end

g.test_chunk_gives_exactly_what_was_asked = function()
    -- Считается байтами, а не знаками: тело письма приходит длиной
    -- в байтах, и резать его по знакам значит разъехаться на первой
    -- же кириллице.
    local piece, rest = buffer.take('письмо', buffer.request({ chunk = 6 }))

    t.assert_equals(piece, 'пис')
    t.assert_equals(rest, 'ьмо')
end

g.test_chunk_waits_until_there_is_enough = function()
    local piece, rest = buffer.take('три', buffer.request({ chunk = 10 }))

    t.assert_equals(piece, nil)
    t.assert_equals(rest, 'три')
end

g.test_empty_chunk_is_ready_at_once = function()
    local piece, rest = buffer.take('', buffer.request({ chunk = 0 }))

    t.assert_equals(piece, '')
    t.assert_equals(rest, '')
end

g.test_a_number_means_a_size = function()
    -- Так пишут те, кто привык к socket:read(4).
    t.assert_equals(buffer.request(4).chunk, 4)
end

g.test_size_alongside_delimiter_caps_the_line = function()
    -- «До строки, но не длиннее»: защита от сервера, у которого строки
    -- не кончаются.
    local request = buffer.request({ delimiter = '\r\n', chunk = 4 })

    t.assert_equals(buffer.take('123456', request), '1234')
    t.assert_equals(buffer.take('12\r\n456', request), '12\r\n', 'разделитель раньше предела')
end

g.test_request_demands_to_know_how_much = function()
    t.assert_str_contains(select(2, buffer.request({})), 'не сказано, сколько читать')
    t.assert_str_contains(select(2, buffer.request(nil)), 'не сказано, сколько читать')
    t.assert_str_contains(select(2, buffer.request('строку')), 'не сказано, сколько читать')
end

g.test_request_refuses_nonsense = function()
    t.assert_str_contains(select(2, buffer.request({ delimiter = '' })), 'непустой строкой')
    t.assert_str_contains(select(2, buffer.request({ delimiter = 17 })), 'непустой строкой')
    t.assert_str_contains(select(2, buffer.request({ chunk = -1 })), 'неотрицательным')
    t.assert_str_contains(select(2, buffer.request({ chunk = 1.5 })), 'неотрицательным')
    t.assert_str_contains(select(2, buffer.request({ chunk = 'много' })), 'неотрицательным')
end

g.test_delimiter_is_taken_as_plain_text = function()
    -- Точка в разделителе — точка, а не «любой знак»: иначе ответ
    -- почтового сервера разрезался бы где попало.
    local piece = buffer.take('a.b\r\n.\r\n', buffer.request({ delimiter = '\r\n.\r\n' }))

    t.assert_equals(piece, 'a.b\r\n.\r\n')
end

g.test_endless_line_does_not_eat_the_node = function()
    -- Сервер, который не шлёт разделитель, — сломанный или недобрый:
    -- копить за ним до конца памяти нельзя.
    local request = buffer.request({ delimiter = '\r\n', limit = 8 })
    local piece, rest, err = buffer.take('девять!!!', request)

    t.assert_equals(piece, nil)
    t.assert_equals(rest, 'девять!!!')
    t.assert_str_contains(err, 'разделитель так и не пришёл')
end

g.test_limit_defaults_to_a_megabyte = function()
    t.assert_equals(buffer.request({ delimiter = '\n' }).limit, buffer.LIMIT)
    t.assert_equals(buffer.LIMIT, 1024 * 1024)
end

g.test_delimiter_is_looked_for_literally = function()
    -- Разделитель — байты, а не шаблон: сервер вправе разделять ответы
    -- знаком процента или точкой, и искать их как шаблон значит резать
    -- поток в случайных местах.
    local request = buffer.request({ delimiter = '%d' })
    local piece, rest = buffer.take('a1b%dc', request)

    t.assert_equals(piece, 'a1b%d')
    t.assert_equals(rest, 'c')
end

g.test_size_limits_a_line_that_never_ends = function()
    -- Размер вместе с разделителем — это «до строки, но не длиннее»:
    -- так вызывающий защищается от сервера, у которого строки
    -- не кончаются. Отдаётся ровно затребованное, остаток — весь хвост.
    local request = buffer.request({ delimiter = '\r\n', chunk = 4 })
    local piece, rest = buffer.take('abcdefg', request)

    t.assert_equals(piece, 'abcd')
    t.assert_equals(rest, 'efg')

    -- Ровно затребованное — уже готовый кусок, а не «подожди ещё байт».
    local exact, nothing = buffer.take('abcd', request)

    t.assert_equals(exact, 'abcd')
    t.assert_equals(nothing, '')
end

g.test_limit_is_reached_but_not_passed = function()
    -- Предел — это «больше нельзя», а не «столько нельзя»: накопленное
    -- ровно по пределу ещё имеет право дождаться разделителя.
    local request = buffer.request({ delimiter = '\r\n', limit = 4 })
    local piece, rest, err = buffer.take('abcd', request)

    t.assert_equals(piece, nil)
    t.assert_equals(rest, 'abcd')
    t.assert_equals(err, nil)

    local nothing, kept, overflow = buffer.take('abcde', request)

    t.assert_equals(nothing, nil)
    t.assert_equals(kept, 'abcde')
    t.assert_str_contains(overflow, 'разделитель так и не пришёл')
end
