--- Чем кончился вызов OpenSSL и как сказать об этом человеку.
---
--- OpenSSL отвечает числом, и число это значит не «плохо», а «что делать
--- дальше». Два кода из пяти — вовсе не ошибки: они говорят, что на
--- неблокирующем дескрипторе пока нечего читать или некуда писать, и тот
--- же самый вызов надо повторить, когда дескриптор будет готов. Перепутать
--- их с отказом значит рвать исправные соединения на ровном месте; крутить
--- на них цикл значит занять весь поток ожиданием.
---
--- Поэтому здесь коды превращаются в состояния, а состояния — это словарь,
--- на котором написан весь остальной пакет. Рядом с ними одно слово
--- о причине отказа — то, по которому вызывающий решает, повторять ли.
--- Модуль чистый: ни ffi, ни сокета, ни библиотеки.

local Module = {}

--- Вызов удался.
Module.DONE = 'done'

--- Повторить, когда на дескрипторе появятся данные.
Module.WANT_READ = 'want_read'

--- Повторить, когда в дескриптор можно будет писать.
Module.WANT_WRITE = 'want_write'

--- Другая сторона закончила разговор: читать больше нечего.
Module.CLOSED = 'closed'

--- Отказ, дальше по этому соединению ничего не будет.
Module.FAILED = 'failed'

--- Род отказа: сертификат другой стороны не принят.
---
--- Не состояние, а причина рядом с ним: соединению после отказа всё
--- равно дальше некуда, а вызывающему важно, лечит ли отказ время.
--- Моргнувшая сеть поднимется сама, а самоподписанный сертификат или
--- сертификат на чужое имя останутся теми же, сколько ни повторяй,
--- и повторы до конца срока только прячут настройку, которую надо чинить.
--- Словом, а не текстом: текст причины меняется вместе с OpenSSL, и сверка
--- с ним однажды перестала бы узнавать отказ, ничем себя не выдав.
Module.UNTRUSTED = 'untrusted'

--- Коды SSL_get_error. Имена оставлены как в OpenSSL: их ищут в её
--- документации, а перевод названия сделал бы поиск невозможным.
local SSL_ERROR_NONE = 0
local SSL_ERROR_SSL = 1
local SSL_ERROR_WANT_READ = 2
local SSL_ERROR_WANT_WRITE = 3
local SSL_ERROR_SYSCALL = 5
local SSL_ERROR_ZERO_RETURN = 6

--- Как назвать код в сообщении.
local NAMES = {
    [SSL_ERROR_NONE] = 'SSL_ERROR_NONE',
    [SSL_ERROR_SSL] = 'SSL_ERROR_SSL',
    [SSL_ERROR_WANT_READ] = 'SSL_ERROR_WANT_READ',
    [SSL_ERROR_WANT_WRITE] = 'SSL_ERROR_WANT_WRITE',
    [4] = 'SSL_ERROR_WANT_X509_LOOKUP',
    [SSL_ERROR_SYSCALL] = 'SSL_ERROR_SYSCALL',
    [SSL_ERROR_ZERO_RETURN] = 'SSL_ERROR_ZERO_RETURN',
}

--- Что означает код и что делать дальше.
---
--- SSL_ERROR_SYSCALL с пустой очередью ошибок — это обрыв TCP без
--- прощания: другая сторона закрыла сокет, не прислав close_notify.
--- Строго говоря, такой конец неотличим от обрезания потока посередине
--- злоумышленником, и строгий клиент обязан считать его отказом. Здесь
--- он считается концом данных, и вот почему: так заканчивают разговор
--- едва ли не все почтовые серверы, и строгость превратила бы каждую
--- удачную отправку письма в отказ. Защита от обрезания остаётся на
--- протоколе выше — тот, кто ждал от сервера подтверждения и не получил
--- его, обязан считать отправку неудавшейся, и это он видит сам.
---@param code number Что вернул SSL_get_error
---@param queued boolean|nil Были ли записи в очереди ошибок OpenSSL
---@return string Одно из состояний модуля
function Module.of(code, queued)
    if code == SSL_ERROR_NONE then
        return Module.DONE
    end

    if code == SSL_ERROR_WANT_READ then
        return Module.WANT_READ
    end

    if code == SSL_ERROR_WANT_WRITE then
        return Module.WANT_WRITE
    end

    if code == SSL_ERROR_ZERO_RETURN then
        return Module.CLOSED
    end

    if code == SSL_ERROR_SYSCALL and not queued then
        return Module.CLOSED
    end

    return Module.FAILED
end

--- Человеческая причина отказа.
---
--- Номер кода в отчёте бесполезен: по нему ничего не понять, не открыв
--- заголовки OpenSSL. Поэтому в строку попадает всё, что знает
--- библиотека: название кода, разобранный текст проверки сертификата
--- и сами записи из очереди ошибок. Очередь идёт последней — её читает
--- тот, кто полез разбираться, а первым идёт то, что объясняет отказ
--- без OpenSSL под рукой.
---@param action string Что делали: «рукопожатие TLS» и подобное
---@param code number|nil Что вернул SSL_get_error
---@param messages string[]|nil Очередь ошибок OpenSSL
---@param verify string|nil Разбор SSL_get_verify_result, если проверка не прошла
---@return string
function Module.reason(action, code, messages, verify)
    local parts = {}

    if verify ~= nil and verify ~= '' then
        table.insert(parts, ('сертификат не принят: %s'):format(verify))
    end

    for _, message in ipairs(messages or {}) do
        table.insert(parts, message)
    end

    if #parts == 0 then
        -- Ни очереди, ни разбора проверки: назвать код — единственное,
        -- что осталось, и это лучше, чем «что-то пошло не так».
        table.insert(parts, NAMES[code] or ('код %s'):format(tostring(code)))
    end

    return ('%s не удалось: %s'):format(action, table.concat(parts, '; '))
end

return Module
