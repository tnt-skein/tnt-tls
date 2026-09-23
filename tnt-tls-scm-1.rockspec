rockspec_format = '3.0'

package = 'tnt-tls'
version = 'scm-1'

source = {
    url = 'git+https://github.com/tnt-skein/tnt-tls.git',
    branch = 'main',
}

description = {
    summary = 'TLS поверх сокета в Tarantool Community Edition: системная OpenSSL через FFI, ожидание файберное',
    detailed = [[
        В Community Edition прикладному коду шифровать нечем: модуля ssl
        там нет, а шифрование iproto доступно только ядру Enterprise
        Edition. Всё, что ходит по TCP из Lua, — почта по SMTP, IMAP
        и POP3, запросы к чужим службам — уходит открытым текстом вместе
        с паролями учётных записей. Пакет поднимает TLS средствами,
        которые в Community Edition есть: системная OpenSSL берётся через
        FFI.

        Два входа. tls.connect открывает сокет и сразу поднимает TLS —
        для портов, где шифрование начинается с первого байта (465, 993,
        995). tls.wrap поднимает TLS поверх уже открытого сокета — так
        работает STARTTLS. Соединение читает по разделителю и по размеру,
        как обычный сокет, пишет строку целиком, прощается в обе стороны
        и называет договорённые шифр и версию протокола.

        Сертификат проверяется по умолчанию, имя узла сверяет сама
        OpenSSL, SNI шлётся, ниже TLS 1.2 соединение не опускается;
        доверенные корни можно заменить своими. Ожидание готовности
        дескриптора файберное: блокирующий SSL_read остановил бы не файбер,
        а весь узел. Срок назначается на каждую операцию.

        Библиотека ищется по списку имён для Linux и macOS, путь можно
        задать переменной TNT_TLS_LIBSSL. Зависит от tnt-clock (часы
        срока), tnt-env (чтение TNT_TLS_LIBSSL, в том числе из .env)
        и tnt-external (подмена слоя OpenSSL, сети и часов в проверках).
        Покрытие строк и убитых мутантов — 100 %.
    ]],
    homepage = 'https://github.com/tnt-skein/tnt-tls',
    issues_url = 'https://github.com/tnt-skein/tnt-tls/issues',
    maintainer = 'tnt-skein',
    license = 'MIT',
    labels = { 'tarantool', 'tls', 'ssl', 'openssl', 'ffi', 'starttls', 'socket' },
}

dependencies = {
    'lua >= 5.1',
    -- Монотонные часы и время планировщика для срока операции.
    'tnt-clock',
    -- Путь к libssl из переменной TNT_TLS_LIBSSL, в том числе строкой в .env.
    'tnt-env',
    -- Подмена слоя OpenSSL, сети, часов и загрузки библиотеки в проверках.
    'tnt-external',
}

build = {
    type = 'builtin',
    modules = {
        ['tnt.tls'] = 'tnt/tls.lua',
        ['tnt.tls.buffer'] = 'tnt/tls/buffer.lua',
        ['tnt.tls.library'] = 'tnt/tls/library.lua',
        ['tnt.tls.link'] = 'tnt/tls/link.lua',
        ['tnt.tls.openssl'] = 'tnt/tls/openssl.lua',
        ['tnt.tls.options'] = 'tnt/tls/options.lua',
        ['tnt.tls.outcome'] = 'tnt/tls/outcome.lua',
    },
}
