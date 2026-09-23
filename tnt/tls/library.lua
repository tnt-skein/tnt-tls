--- Где искать libssl и как её загрузить.
---
--- Tarantool собран с OpenSSL, но прикладному коду её символы не отданы:
--- модуль `ssl` есть только в Enterprise Edition. Поэтому библиотека
--- берётся у системы через `ffi.load` — своим экземпляром, рядом с тем,
--- которым пользуется ядро.
---
--- Один жёстко вписанный путь не годится. На macOS системная
--- /usr/lib/libssl.dylib — это LibreSSL от Apple, другой породы
--- и другой давности; настоящая OpenSSL лежит в каталоге Homebrew, и
--- каталог этот разный на Apple Silicon и на Intel. На Linux имя файла
--- несёт версию: libssl.so.3 у одних дистрибутивов, libssl.so.1.1
--- у других, а безверсионная libssl.so есть только там, где поставлен
--- пакет для разработки. Поэтому кандидатов список, и берётся первый,
--- который загрузился.
---
--- Модуль намеренно ничего не знает ни про ffi, ни про jit: род системы
--- и способ загрузки приходят снаружи. Так выбор библиотеки проверяется
--- на машине, где OpenSSL нет вовсе.

local Module = {}

--- Переменная окружения с путём к libssl.
---
--- Нужна там, где библиотека лежит не там, где её ищут: свой образ,
--- нестандартный префикс, две OpenSSL рядом.
Module.ENV_OVERRIDE = 'TNT_TLS_LIBSSL'

--- Куда смотреть на macOS.
---
--- Сначала каталоги Homebrew с явной версией: там лежит настоящая
--- OpenSSL. Безверсионные имена в конце — на случай, когда библиотеку
--- поставили как-то иначе и она видна загрузчику по имени.
local MACOS = {
    '/opt/homebrew/opt/openssl@3/lib/libssl.dylib',
    '/opt/homebrew/opt/openssl@1.1/lib/libssl.dylib',
    '/usr/local/opt/openssl@3/lib/libssl.dylib',
    '/usr/local/opt/openssl@1.1/lib/libssl.dylib',
    'libssl.3.dylib',
    'libssl.1.1.dylib',
}

--- Куда смотреть на Linux и везде, где имена библиотек устроены так же.
---
--- Версия в имени идёт раньше безверсионного имени: libssl.so — это
--- символьная ссылка из пакета для разработки, и на рабочем узле её
--- обычно нет, а libssl.so.3 есть всегда.
local LINUX = {
    'libssl.so.3',
    'libssl.so.1.1',
    'libssl.so',
}

--- Перечень имён, которые стоит попробовать.
---
--- Путь из переменной окружения идёт первым, но не отменяет остальные:
--- опечатка в переменной не должна лишать узел шифрования вовсе.
---@param os_name string|nil Род системы, как его называет jit.os
---@param override string|nil Путь, заданный руками
---@return string[]
function Module.candidates(os_name, override)
    local names = {}

    if type(override) == 'string' and override ~= '' then
        table.insert(names, override)
    end

    local known = os_name == 'OSX' and MACOS or LINUX

    for _, name in ipairs(known) do
        table.insert(names, name)
    end

    return names
end

--- Загружает первую библиотеку, которая поддалась.
---
--- Отказ возвращается причиной со списком того, что пробовали: «TLS
--- недоступен» без перечня мест — это сообщение, по которому никто
--- ничего не починит.
---@param names string[] Что пробовать
---@param open fun(name: string): any Способ загрузки, обычно ffi.load
---@return any|nil lib
---@return string|nil err
function Module.load(names, open)
    local tried = {}

    for _, name in ipairs(names) do
        -- Через pcall: ffi.load на отсутствующем файле не возвращает nil,
        -- а поднимает ошибку, и первое же промахнувшееся имя оборвало бы
        -- перебор на полпути.
        local ok, lib = pcall(open, name)

        if ok and lib ~= nil then
            return lib
        end

        table.insert(tried, name)
    end

    return nil,
        (
            'OpenSSL не нашлась: не загрузилась ни одна из библиотек (%s). '
            .. 'Поставьте её (brew install openssl@3 либо пакет libssl3) '
            .. 'или укажите путь переменной окружения %s'
        ):format(table.concat(tried, ', '), Module.ENV_OVERRIDE)
end

return Module
