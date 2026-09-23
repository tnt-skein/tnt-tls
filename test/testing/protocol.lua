--- Двойники протоколов: сервер отвечает заранее написанным.
---
--- Протокол — это разговор, и проверять его надо разговором: двойник
--- помнит, что сказали мы, и отдаёт то, что должен был бы ответить
--- сервер. Настоящий сокет для этого не нужен, а вот порядок реплик —
--- нужен весь: переходы, повторы и ошибки видны только по нему.
---
--- Двойник показывает лишь, что мы правильно разговариваем сами с собой,
--- поэтому рядом с ним идут проверки против настоящей службы — отдельным
--- файлом `*_live_test.lua` и с пропуском, если службы нет.

local Module = {}

--- Чем двойник отвечает, когда сценарий кончился, а сервер всё спрашивают.
Module.SILENCE = 'сервер молчит'

---@class TntTestingScript
---@field next fun(): any Следующий ответ; кончившийся сценарий — ошибка проверки
---@field taken fun(): integer Сколько ответов уже взято
---@field left fun(): integer Сколько ответов осталось

--- Ответы по порядку.
---
--- Значение отдаётся как есть, функция зовётся, и отдаётся её ответ —
--- так двойник отвечает тем, что решается в миг вопроса, и так же он
--- бросает: `function() error(...) end`. Кончившийся сценарий — ошибка
--- проверки, а не молчаливый успех: код, сходивший к серверу лишний раз,
--- обязан об этом сказать.
---@param answers any[]
---@return TntTestingScript
function Module.script(answers)
    local at = 0

    return {
        next = function()
            at = at + 1

            local answer = answers[at]

            if answer == nil then
                error(('двойник сервера не знает ответа №%d'):format(at))
            end

            if type(answer) == 'function' then
                return answer()
            end

            return answer
        end,

        taken = function()
            return at
        end,

        left = function()
            return #answers - at
        end,
    }
end

--- Первые `size` байт текста.
---
--- Начало задано отрицательным отсчётом от конца, а не единицей: `sub(1, n)`
--- и `sub(0, n)` в Lua неотличимы, и мутант с нулём жил бы вечно.
---@param text string
---@param size integer
---@return string
local function head(text, size)
    return text:sub(-#text, size)
end

--- Запись и закрытие, общие для соединения и для сокета: у обоих они
--- одинаковы и живут здесь, чтобы не разойтись между двумя двойниками.
---@param said table Куда складывать сказанное
---@return fun(text: string): integer write
---@return fun() close
local function saying(said)
    return function(text)
        table.insert(said, (text:gsub('\r\n$', '')))

        return #text
    end, function()
        said.closed = true
    end
end

--- Следующая реплика сервера или молчание, когда сценарий кончился.
---
--- Молчание — отказ парой, а не ошибка проверки: сервер, переставший
--- отвечать посреди разговора, — обычный сценарий, и код обязан
--- пережить его сам.
---@param replies string[]
---@return fun(): string|nil, string|nil
local function replying(replies)
    local at = 0

    return function()
        at = at + 1

        local reply = replies[at]

        if reply == nil then
            return nil, Module.SILENCE
        end

        return reply
    end
end

---@class TntTestingConversation
---@field read_line fun(): string|nil, string|nil Строка ответа
---@field read_chunk fun(size: integer): string|nil, string|nil Не больше `size` байт ответа
---@field write fun(text: string): integer Сказать серверу; CRLF на конце в `said` не попадает
---@field close fun() Закрыть; в `said.closed` остаётся отметка

--- Двойник соединения: сервер отвечает строками по одной на чтение.
---@param replies string[] Что отвечает сервер, по реплике на чтение
---@return TntTestingConversation link
---@return table said Что мы сказали серверу, по порядку
function Module.conversation(replies)
    local said = {}
    local reply = replying(replies)
    local write, close = saying(said)

    return {
        read_line = function()
            return reply()
        end,

        read_chunk = function(size)
            local line, err = reply()

            if line == nil then
                return nil, err
            end

            return head(line, size)
        end,

        write = write,
        close = close,
    },
        said
end

---@class TntTestingSocket
---@field read fun(self: table, opts: table|integer, timeout: number|nil): string|nil, string|nil
---@field write fun(self: table, text: string): integer
---@field close fun(self: table)

--- Двойник сокета: то, что отдаёт `socket.tcp_connect`.
---
--- Нужен там, где проверяется не разговор, а транспорт: тот оборачивает
--- сокет, и подменять надо именно сокет. Чтение с `delimiter` отдаёт
--- реплику с ним на конце, чтение с `chunk` или числом — не больше
--- стольких байт реплики, как у настоящего.
---@param replies string[] Что отвечает сервер, по реплике на чтение
---@return TntTestingSocket socket
---@return table said Что мы сказали серверу, по порядку
function Module.socket(replies)
    local said = {}
    local reply = replying(replies)
    local write, close = saying(said)

    return {
        read = function(_, opts)
            local line, err = reply()

            if line == nil then
                return nil, err
            end

            if type(opts) == 'number' then
                return head(line, opts --[[@as integer]])
            end

            if opts.chunk ~= nil then
                return head(line, opts.chunk)
            end

            return line .. opts.delimiter
        end,

        write = function(_, text)
            return write(text)
        end,

        close = function()
            close()
        end,
    },
        said
end

return Module
