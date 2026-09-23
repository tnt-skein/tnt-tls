--- Слой FFI: разговор с OpenSSL.
---
--- Здесь и только здесь пакет знает про ffi. Наружу выдаётся словарь
--- действий — открыть, поздороваться, прочитать, записать, попрощаться,
--- освободить, — и каждое отвечает состоянием из `tnt.tls.outcome`,
--- а не кодом OpenSSL; рядом два вопроса без состояния: чем договорились
--- шифровать и не осталось ли в OpenSSL непрочитанного. Всё, что делается
--- с этими состояниями — ожидание готовности дескриптора, сроки,
--- накопление прочитанного, — живёт в `tnt.tls.link` и проверяется
--- без OpenSSL вовсе.
---
--- Дескриптор отдаётся OpenSSL готовым: сокет открывает и закрывает
--- вызывающий, а SSL_set_fd заводит поверх него BIO с пометкой
--- BIO_NOCLOSE. Поэтому SSL_free дескриптор не закроет, и закрыть его
--- обязан тот, кто открыл.
---
--- Очередь ошибок OpenSSL — на поток, а не на соединение, и осушать её
--- надо сразу после неудавшегося вызова, до всякого переключения
--- файберов. Иначе соседний файбер вычитает наши ошибки себе, а мы
--- прочтём его — и оба получат причину от чужого соединения.

local ffi = require('ffi')

local env = require('tnt.env')
local library = require('tnt.tls.library')
local outcome = require('tnt.tls.outcome')
local external = require('tnt.external')

local Module = {}

-- Объявления C попадают в общее для всего процесса пространство ffi,
-- и повторное объявление типа — ошибка. Тесты грузят модуль заново
-- перед каждой проверкой, а пространство ffi перезагрузку переживает,
-- поэтому пометка отвечает на вопрос «уже объявляли?».
if not pcall(ffi.typeof, 'struct tnt_tls_declared') then
    ffi.cdef([[
        struct tnt_tls_declared { int unused; };

        typedef struct ssl_ctx_st SSL_CTX;
        typedef struct ssl_st SSL;
        typedef struct ssl_method_st SSL_METHOD;
        typedef struct ssl_cipher_st SSL_CIPHER;

        const SSL_METHOD *TLS_client_method(void);
        SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
        void SSL_CTX_free(SSL_CTX *ctx);
        long SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg);
        int SSL_CTX_set_default_verify_paths(SSL_CTX *ctx);
        int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *ca_file, const char *ca_path);

        SSL *SSL_new(SSL_CTX *ctx);
        void SSL_free(SSL *ssl);
        int SSL_set_fd(SSL *ssl, int fd);
        long SSL_ctrl(SSL *ssl, int cmd, long larg, void *parg);
        int SSL_set1_host(SSL *ssl, const char *hostname);
        void SSL_set_verify(SSL *ssl, int mode, void *callback);
        int SSL_connect(SSL *ssl);
        int SSL_read(SSL *ssl, void *buf, int num);
        int SSL_write(SSL *ssl, const void *buf, int num);
        int SSL_shutdown(SSL *ssl);
        int SSL_get_error(const SSL *ssl, int ret);
        long SSL_get_verify_result(const SSL *ssl);
        const char *SSL_get_version(const SSL *ssl);
        const SSL_CIPHER *SSL_get_current_cipher(const SSL *ssl);
        const char *SSL_CIPHER_get_name(const SSL_CIPHER *cipher);

        unsigned long ERR_get_error(void);
        void ERR_error_string_n(unsigned long e, char *buf, size_t len);
        void ERR_clear_error(void);
        const char *X509_verify_cert_error_string(long n);
    ]])
end

-- Сертификат клиента и вопрос о непрочитанном появились позже пометки,
-- и под неё они не встают: прежняя копия пакета, загруженная в процесс
-- раньше (установленная рядом с исходниками), ставит пометку без них,
-- и они остались бы необъявленными. Функцию ffi объявляет повторно молча,
-- поэтому этот кусок объявляется всякий раз, без пометки.
--
-- Молча — и оставляя в силе первое объявление. Часть тех же функций
-- объявляет своими подписями и рок `http` (сервер HTTPS), и на узле
-- с сервером HTTP его объявления приходят раньше. Поэтому подписи здесь —
-- ровно как в OpenSSL, а аргументы подаются так, чтобы годиться под них:
-- данные для пароля ключа — `void *`, не строка.
ffi.cdef([[
    int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
    int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
    int SSL_CTX_check_private_key(const SSL_CTX *ctx);
    void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *ctx, void *userdata);
    int SSL_has_pending(const SSL *ssl);
]])

--- Команды SSL_ctrl и SSL_CTX_ctrl. Имена как в заголовках OpenSSL:
--- в её документации они ищутся именно так.
local SSL_CTRL_MODE = 33
local SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
local SSL_CTRL_SET_MIN_PROTO_VERSION = 123
local TLSEXT_NAMETYPE_host_name = 0

--- Частями писать разрешено, буфер записи разрешено двигать.
---
--- Без первого SSL_write обязан быть повторён ровно теми же аргументами,
--- что и в прошлый раз, — а повторяем мы его после ожидания готовности,
--- когда часть уже ушла. Без второго LuaJIT, отдавший указатель внутрь
--- строки, однажды получил бы отказ на повторе.
local SSL_MODE_ENABLE_PARTIAL_WRITE = 1
local SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER = 2

--- Требовать сертификат и проверять его.
local SSL_VERIFY_PEER = 1

--- Ключ клиента читается из текста PEM.
local SSL_FILETYPE_PEM = 1

--- Пароль ключа клиента: пустой.
---
--- Без него OpenSSL, встретив ключ под паролем, спросила бы пароль
--- у терминала и ждала ответа, остановив весь узел, — у узла, запущенного
--- из терминала, ответа не дождаться никогда. Пустой пароль не подходит
--- ни к одному ключу под паролем, и чтение такого ключа — отказ сразу.
--- Строка живёт вместе с модулем: OpenSSL держит на неё указатель.
local NO_PASSWORD = ''

--- Ниже TLS 1.2 не опускаться.
---
--- TLS 1.0 и 1.1 сняты с поддержки и сломаны; сервер, который умеет
--- только их, — это либо музейный экспонат, либо не тот сервер.
local TLS1_2_VERSION = 0x0303

--- Сколько байт брать за одно чтение.
---
--- Ровно запись TLS: больше OpenSSL за раз всё равно не отдаст, меньше —
--- лишний оборот цикла на каждую запись.
local READ_SIZE = 16 * 1024

--- Сколько места на строку ошибки OpenSSL. Её собственный совет — 256.
local ERROR_TEXT_SIZE = 256

--- Единожды загруженная библиотека.
---
--- Это единственное состояние, общее для всех соединений: dlopen одного
--- и того же файла на каждое соединение ничего бы не дал, кроме работы.
---@type any
local loaded = nil

--- Почему её нет, если её нет.
---@type string|nil
local missing = nil

--- Внешние средства: загрузка библиотеки и сведения о системе.
local source = external.install(Module, {
    -- Сама `ffi.load`, а не обёртка над ней: обёртка ничего не добавляла,
    -- а её `return` проверить нечем — без библиотеки живые проверки
    -- пропускаются, и поломка загрузки выглядела бы пропуском.
    open = ffi.load,

    -- Род системы значением, как его называет `jit.os`, а не обёрткой
    -- с `return`: на Linux пустота вместо него выбрала бы тот же список
    -- имён, и поломку обёртки проверить было бы нечем.
    system = require('jit').os,

    -- Путь к libssl — через `tnt-env`, а не `os.getenv`: строка в `.env`
    -- действует и на узле, поднятом не через `make`. Негодный `.env`
    -- отсюда бросает, как и всякое первое чтение окружения, — это договор
    -- `tnt-env`: такой файл обязан останавливать старт, а не молчать.
    getenv = function(name)
        return env.string(name)
    end,
})

--- Библиотека OpenSSL либо причина, по которой её нет.
---@return any|nil lib
---@return string|nil err
function Module.library()
    if loaded ~= nil then
        return loaded
    end

    if missing ~= nil then
        return nil, missing
    end

    local names = library.candidates(source().system, source().getenv(library.ENV_OVERRIDE))
    local lib, err = library.load(names, source().open)

    if lib == nil then
        missing = err

        return nil, missing
    end

    loaded = lib

    return loaded
end

--- Забывает загруженное. Нужно тестам, подменяющим способ загрузки.
function Module.forget()
    loaded = nil
    missing = nil
end

--- Осушает очередь ошибок OpenSSL.
---
--- Целиком: в очереди бывает несколько записей, и объясняет отказ
--- обычно первая, а не последняя. Оставленный хвост достался бы
--- следующему вызову как его собственная ошибка.
---@param lib any
---@return string[]
function Module.queue(lib)
    local messages = {}
    local text = ffi.new('char[?]', ERROR_TEXT_SIZE)

    while true do
        local code = lib.ERR_get_error()

        if code == 0 then
            break
        end

        lib.ERR_error_string_n(code, text, ERROR_TEXT_SIZE)
        table.insert(messages, ffi.string(text))
    end

    return messages
end

---@class TntTlsSession
---@field lib any Загруженная OpenSSL
---@field ctx any SSL_CTX этого соединения
---@field ssl any SSL этого соединения
---@field buffer any Куда читать
---@field size integer Размер буфера чтения
---@field verify boolean Проверяется ли сертификат сервера

--- Разбирает неудавшийся вызов.
---
--- Очередь осушается всегда, даже когда состояние окажется не отказом:
--- записи, оставленные в ней, достались бы следующему вызову.
---@param session TntTlsSession
---@param rc number Что вернул вызов OpenSSL
---@param action string Что делали
---@return string state
---@return string|nil err
---@return string|nil kind `outcome.UNTRUSTED`, если не принят сертификат другой стороны
function Module.diagnose(session, rc, action)
    local lib = session.lib
    local code = tonumber(lib.SSL_get_error(session.ssl, rc))

    -- SSL_get_error отвечает целым числом всегда: пустоты здесь
    -- не бывает, а проверяющий типов о C не знает.
    ---@cast code number

    local messages = Module.queue(lib)
    local state = outcome.of(code, #messages > 0)

    if state ~= outcome.FAILED then
        return state
    end

    -- Разбор проверки сертификата спрашивается только на отказе:
    -- «ok» на исправном соединении ничего не объясняет, а на отказе
    -- именно он говорит, что сертификат самоподписанный или выписан
    -- не на то имя. И только когда проверка включена: без неё OpenSSL
    -- всё равно пишет вердикт, но отказа он не вызывал, и «сертификат
    -- не принят» в тексте увёл бы разбор не туда — например, от сервера,
    -- не принявшего наш сертификат, к его собственному.
    local verdict = tonumber(lib.SSL_get_verify_result(session.ssl))
    local verify = nil

    if session.verify and verdict ~= 0 then
        verify = ffi.string(lib.X509_verify_cert_error_string(verdict))
    end

    -- Тот же вердикт, что пишет «сертификат не принят» в текст, называет
    -- и род отказа: вердикт OpenSSL ставит, только проверив сертификат,
    -- а не принятый сертификат рвёт рукопожатие на этом же шаге.
    return state, outcome.reason(action, code, messages, verify), verify and outcome.UNTRUSTED
end

--- Готовит доверенные корни.
---@param lib any
---@param ctx any
---@param settings TntTlsSettings
---@return string|nil err
local function trust(lib, ctx, settings)
    if settings.ca_file ~= nil or settings.ca_path ~= nil then
        -- Указанные корни заменяют системные, а не добавляются к ним:
        -- тот, кто назвал свой удостоверяющий центр, обычно как раз
        -- и хочет, чтобы больше никакой другой не подошёл.
        if lib.SSL_CTX_load_verify_locations(ctx, settings.ca_file, settings.ca_path) ~= 1 then
            return outcome.reason('чтение доверенных корней', nil, Module.queue(lib), nil)
        end

        return nil
    end

    if lib.SSL_CTX_set_default_verify_paths(ctx) ~= 1 then
        return outcome.reason(
            'чтение доверенных корней системы',
            nil,
            Module.queue(lib),
            nil
        )
    end

    return nil
end

--- Заводит сертификат клиента и его ключ.
---
--- Сертификат читается с цепочкой: промежуточные сертификаты, лежащие
--- в том же файле за ним, уходят серверу вместе с ним, и сервер, который
--- знает только корень, всё же может построить путь до него. Сверка ключа
--- с сертификатом — отдельным шагом: ключ другого рода (EC при сертификате
--- RSA) OpenSSL принимает молча, а отказ сервера узнался бы только
--- посреди рукопожатия, без слова о ключе.
---
--- Пути в тексте отказа — чтобы было видно, какой файл чинить; путь
--- к ключу — не ключ.
---@param lib any
---@param ctx any
---@param settings TntTlsSettings Сертификат задан
---@return string|nil err
local function identify(lib, ctx, settings)
    if lib.SSL_CTX_use_certificate_chain_file(ctx, settings.cert_file) ~= 1 then
        return outcome.reason(
            ('чтение сертификата клиента %s'):format(settings.cert_file),
            nil,
            Module.queue(lib),
            nil
        )
    end

    lib.SSL_CTX_set_default_passwd_cb_userdata(ctx, ffi.cast('void *', ffi.cast('const char *', NO_PASSWORD)))

    if lib.SSL_CTX_use_PrivateKey_file(ctx, settings.key_file, SSL_FILETYPE_PEM) ~= 1 then
        return outcome.reason(
            ('чтение ключа клиента %s'):format(settings.key_file),
            nil,
            Module.queue(lib),
            nil
        )
    end

    if lib.SSL_CTX_check_private_key(ctx) ~= 1 then
        return outcome.reason(
            ('сопоставление ключа %s с сертификатом %s'):format(
                settings.key_file,
                settings.cert_file
            ),
            nil,
            Module.queue(lib),
            nil
        )
    end

    return nil
end

--- Открывает защищённый разговор поверх готового дескриптора.
---
--- SSL_CTX заводится свой на каждое соединение. Общий стоил бы дешевле —
--- доверенные корни системы читаются при его настройке, — но означал бы
--- состояние, общее для всех соединений сразу: настройки одного
--- вызывающего доставались бы другому, а опечатка в доверенных корнях
--- отравляла бы весь узел до перезапуска.
---@param fd integer Дескриптор открытого сокета
---@param settings TntTlsSettings
---@return TntTlsSession|nil session
---@return string|nil err
function Module.open(fd, settings)
    local lib, err = Module.library()

    if lib == nil then
        return nil, err
    end

    lib.ERR_clear_error()

    local ctx = lib.SSL_CTX_new(lib.TLS_client_method())

    if ctx == nil then
        return nil, outcome.reason('подготовка TLS', nil, Module.queue(lib), nil)
    end

    -- Освобождение вешается сразу: между этой строкой и следующей ошибкой
    -- есть десяток выходов, и забытый на одном из них SSL_CTX никто бы
    -- не хватился — он не виден ни одному счётчику Lua.
    ctx = ffi.gc(ctx, lib.SSL_CTX_free)

    lib.SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, TLS1_2_VERSION, nil)
    lib.SSL_CTX_ctrl(ctx, SSL_CTRL_MODE, SSL_MODE_ENABLE_PARTIAL_WRITE + SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER, nil)

    if settings.verify then
        local refused = trust(lib, ctx, settings)

        if refused ~= nil then
            return nil, refused
        end
    end

    -- Сертификат клиента не зависит от проверки сервера: сервер спрашивает
    -- его и тогда, когда мы сервер не проверяем.
    if settings.cert_file ~= nil then
        local refused = identify(lib, ctx, settings)

        if refused ~= nil then
            return nil, refused
        end
    end

    local ssl = lib.SSL_new(ctx)

    if ssl == nil then
        return nil, outcome.reason('подготовка TLS', nil, Module.queue(lib), nil)
    end

    ssl = ffi.gc(ssl, lib.SSL_free)

    if lib.SSL_set_fd(ssl, fd) ~= 1 then
        return nil, outcome.reason('привязка TLS к сокету', nil, Module.queue(lib), nil)
    end

    if settings.sni ~= nil then
        -- Без SNI виртуальный сервер отдаёт сертификат не тот, и
        -- проверка имени валится на исправном сервере.
        lib.SSL_ctrl(
            ssl,
            SSL_CTRL_SET_TLSEXT_HOSTNAME,
            TLSEXT_NAMETYPE_host_name,
            ffi.cast('void *', ffi.cast('const char *', settings.sni))
        )
    end

    if settings.verify then
        -- Имя узла сверяет сама OpenSSL. Сверять его после рукопожатия
        -- своими руками значит однажды не сверить: шифрование к тому
        -- времени уже работает, и пропущенная проверка ничем себя
        -- не выдаёт.
        if lib.SSL_set1_host(ssl, settings.host) ~= 1 then
            return nil, outcome.reason('проверка имени узла', nil, Module.queue(lib), nil)
        end

        lib.SSL_set_verify(ssl, SSL_VERIFY_PEER, nil)
    end

    return {
        lib = lib,
        ctx = ctx,
        ssl = ssl,
        buffer = ffi.new('char[?]', READ_SIZE),
        size = READ_SIZE,
        verify = settings.verify,
    }
end

--- Шаг рукопожатия.
---@param session TntTlsSession
---@return string state
---@return string|nil err
---@return string|nil kind `outcome.UNTRUSTED`, если не принят сертификат сервера
function Module.handshake(session)
    session.lib.ERR_clear_error()

    local rc = session.lib.SSL_connect(session.ssl)

    if rc == 1 then
        return outcome.DONE
    end

    return Module.diagnose(session, rc, 'рукопожатие TLS')
end

--- Шаг чтения.
---@param session TntTlsSession
---@return string state
---@return string|nil data
---@return string|nil err
function Module.read(session)
    session.lib.ERR_clear_error()

    local rc = session.lib.SSL_read(session.ssl, session.buffer, session.size)

    if rc > 0 then
        return outcome.DONE, ffi.string(session.buffer, rc)
    end

    local state, err = Module.diagnose(session, rc, 'чтение из TLS')

    return state, nil, err
end

--- Шаг записи.
---
--- Указатель берётся прямо внутрь строки Lua: строки неизменяемы, сборщик
--- LuaJIT их не двигает, и копия была бы лишней работой на каждом письме.
---@param session TntTlsSession
---@param text string Что писать целиком
---@param sent number Сколько уже ушло
---@return string state
---@return number|nil written Сколько ушло за этот шаг
---@return string|nil err
function Module.write(session, text, sent)
    session.lib.ERR_clear_error()

    local from = ffi.cast('const char *', text) + sent
    local rc = session.lib.SSL_write(session.ssl, from, #text - sent)

    if rc > 0 then
        return outcome.DONE, tonumber(rc)
    end

    local state, err = Module.diagnose(session, rc, 'запись в TLS')

    return state, nil, err
end

--- Шаг прощания.
---
--- Единица означает, что попрощались обе стороны; ноль — что своё
--- прощание ушло, а чужого ещё нет, и вызвать надо ещё раз.
---@param session TntTlsSession
---@return string state
function Module.shutdown(session)
    session.lib.ERR_clear_error()

    local rc = session.lib.SSL_shutdown(session.ssl)

    if rc > 0 then
        return outcome.DONE
    end

    if rc == 0 then
        return outcome.CLOSED
    end

    return (Module.diagnose(session, rc, 'закрытие TLS'))
end

--- Отпускает SSL и SSL_CTX.
---
--- Освобождение снимается со сборщика и делается вручную: соединений
--- за час бывают тысячи, и ждать сборки мусора значит держать тысячи
--- буферов OpenSSL, которых не видит ни один счётчик Lua. Сборщику
--- остаётся только забытое — на случай, когда закрыть забыли.
---@param session TntTlsSession
function Module.release(session)
    if session.ssl ~= nil then
        session.lib.SSL_free(ffi.gc(session.ssl, nil))
        session.ssl = nil
    end

    if session.ctx ~= nil then
        session.lib.SSL_CTX_free(ffi.gc(session.ctx, nil))
        session.ctx = nil
    end

    session.buffer = nil
end

--- Осталось ли в OpenSSL что-то, чего соединение ещё не прочло.
---
--- И расшифрованное, и принятое, но не разобранное: записи TLS, пришедшие
--- из сокета, дальше видны только OpenSSL, и сокет о них уже не скажет.
---@param session TntTlsSession
---@return boolean
function Module.buffered(session)
    return session.lib.SSL_has_pending(session.ssl) ~= 0
end

--- Чем договорились шифровать.
---@param session TntTlsSession
---@return { cipher: string|nil, protocol: string|nil }
function Module.describe(session)
    local cipher = session.lib.SSL_get_current_cipher(session.ssl)

    return {
        protocol = ffi.string(session.lib.SSL_get_version(session.ssl)),
        cipher = cipher ~= nil and ffi.string(session.lib.SSL_CIPHER_get_name(cipher)) or nil,
    }
end

return Module
