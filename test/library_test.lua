--- Тесты выбора библиотеки: где искать libssl и что сказать, не найдя.

local t = require('luatest')

local helper = dofile('test/helper.lua')

local g = t.group('tnt.tls.library')

---@type any
local library

g.before_each(function()
    library = helper.load('tnt.tls.library')
end)

g.after_each(function()
    helper.unload()
end)

g.test_macos_looks_in_homebrew_first = function()
    -- Системная /usr/lib/libssl.dylib на macOS — это LibreSSL от Apple,
    -- и её в списке быть не должно вовсе.
    local names = library.candidates('OSX')

    t.assert_equals(names[1], '/opt/homebrew/opt/openssl@3/lib/libssl.dylib')

    for _, name in ipairs(names) do
        t.assert_not_equals(name, '/usr/lib/libssl.dylib', 'LibreSSL от Apple не годится')
    end
end

g.test_linux_prefers_versioned_name = function()
    -- libssl.so — ссылка из пакета для разработки, на рабочем узле её нет.
    local names = library.candidates('Linux')

    t.assert_equals(names[1], 'libssl.so.3')
    t.assert_equals(names[#names], 'libssl.so')
end

g.test_unknown_system_gets_the_usual_names = function()
    -- Незнакомый род системы устроен как Linux чаще, чем как macOS.
    t.assert_equals(library.candidates('BSD'), library.candidates('Linux'))
end

g.test_given_path_goes_first_but_does_not_cancel_the_rest = function()
    -- Опечатка в переменной окружения не должна лишать узел шифрования.
    local names = library.candidates('Linux', '/своя/libssl.so')

    t.assert_equals(names[1], '/своя/libssl.so')
    t.assert_equals(#names, #library.candidates('Linux') + 1)
end

g.test_empty_override_is_no_override = function()
    t.assert_equals(library.candidates('Linux', ''), library.candidates('Linux'))
    t.assert_equals(library.candidates('Linux', 17), library.candidates('Linux'))
end

g.test_first_loadable_wins = function()
    local tried = {}

    local lib = library.load({ 'первая', 'вторая', 'третья' }, function(name)
        table.insert(tried, name)

        if name ~= 'вторая' then
            error('нет такой библиотеки')
        end

        return { name = name }
    end)

    t.assert_equals(lib.name, 'вторая')
    t.assert_equals(
        tried,
        { 'первая', 'вторая' },
        'после удачи перебор прекращается'
    )
end

g.test_load_survives_a_raising_loader = function()
    -- ffi.load на отсутствующем файле не возвращает nil, а поднимает
    -- ошибку: первое же промахнувшееся имя оборвало бы перебор.
    local lib, err = library.load({ 'нет', 'тоже нет' }, function()
        error('cannot open shared object file')
    end)

    t.assert_equals(lib, nil)
    t.assert_str_contains(err, 'нет, тоже нет')
end

g.test_absent_library_names_the_places_and_the_way_out = function()
    local _, err = library.load({ 'libssl.so.3' }, function()
        return nil
    end)

    t.assert_str_contains(err, 'libssl.so.3', 'сказано, где искали')
    t.assert_str_contains(err, library.ENV_OVERRIDE, 'сказано, чем это поправить')
    t.assert_str_contains(err, 'brew install openssl@3')
end
