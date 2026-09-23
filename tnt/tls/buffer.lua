--- Накопленное из сети и правила выдачи.
---
--- Шифрованный поток приходит кусками, которые не совпадают ни со
--- строками протокола, ни с запрошенным размером: одно чтение может
--- принести три ответа сервера сразу или полстроки. Поэтому прочитанное
--- копится, а выдаётся ровно столько, сколько просили, — как это делает
--- `socket:read`, на который построчные протоколы и рассчитаны.
---
--- Модуль чистый: он не читает, а только делит уже прочитанное.

local Module = {}

--- Насколько велика строка, после которой разговор считается сорванным.
---
--- Чтение по разделителю копит до тех пор, пока разделитель не найдётся.
--- Сервер, который его не шлёт — сломанный или недобрый, — так съел бы
--- всю память узла, и остановить это было бы нечем. Мегабайт заведомо
--- больше любой строки почтового протокола; тело письма читается
--- размером, а не разделителем, и под этот предел не попадает.
Module.LIMIT = 1024 * 1024

---@class TntTlsRequest
---@field delimiter string|nil Читать до этой подстроки включительно
---@field chunk integer|nil Читать ровно столько байт
---@field limit number Предел накопления при чтении по разделителю

--- Разбирает, сколько читать.
---
--- Число понимается как размер: так пишут те, кто привык к `socket:read(4)`,
--- и отказывать им нечестно.
---@param opts table|number|nil
---@return TntTlsRequest|nil request
---@return string|nil err
function Module.request(opts)
    if type(opts) == 'number' then
        opts = { chunk = opts }
    end

    if type(opts) ~= 'table' then
        return nil,
            'не сказано, сколько читать: нужен { delimiter = ... } либо { chunk = ... }'
    end

    local delimiter = opts.delimiter

    if delimiter ~= nil and (type(delimiter) ~= 'string' or delimiter == '') then
        return nil, 'разделитель должен быть непустой строкой'
    end

    ---@type integer|nil
    local chunk = nil

    if opts.chunk ~= nil then
        local size = tonumber(opts.chunk)

        if size == nil or size < 0 or size ~= math.floor(size) then
            return nil,
                ('размер должен быть целым неотрицательным числом, а не %s'):format(
                    tostring(opts.chunk)
                )
        end

        -- Целость проверена выше: дальше размер идёт в string.sub,
        -- а тот дробных мест не понимает.
        ---@cast size integer
        chunk = size
    end

    if delimiter == nil and chunk == nil then
        return nil,
            'не сказано, сколько читать: нужен { delimiter = ... } либо { chunk = ... }'
    end

    return { delimiter = delimiter, chunk = chunk, limit = tonumber(opts.limit) or Module.LIMIT }
end

--- Кусок из начала накопленного и остаток за ним.
---
--- Начало среза — `-#data`, а не единица: у единицы мутанты `0` и `1-1`
--- дают тот же срез, а у `-#data` единственный мутант, `+#data`,
--- не загружается.
--- Отрицательное начало, дальнее длины строки, срез прижимает к первому
--- байту, а у пустой строки срез пуст. Размер не длиннее накопленного:
--- его дают поиск разделителя либо проверка `#data >= chunk`.
---@param data string
---@param size integer
---@return string piece
---@return string rest
local function cut(data, size)
    return data:sub(-#data, size), data:sub(size + 1)
end

--- Отделяет готовый кусок от накопленного.
---
--- Разделитель отдаётся вместе с куском: так делает `socket:read`, и тот,
--- кто снимает его сам, не должен гадать, был он или строка кончилась
--- обрывом связи.
---@param data string Что накопилось
---@param request TntTlsRequest
---@return string|nil piece Готовый кусок либо nil, если ждать ещё
---@return string rest Что осталось накопленным
---@return string|nil err Накопленное переросло предел
function Module.take(data, request)
    if request.delimiter ~= nil then
        -- Поиск с начала — без номера места: у единицы мутанты `0` и `1-1`
        -- нашли бы то же самое.
        local _, last = data:find(request.delimiter, nil, true)

        if last ~= nil then
            return cut(data, last)
        end

        -- Размер вместе с разделителем — это «до строки, но не длиннее»:
        -- так вызывающий защищается от сервера, у которого строки
        -- не кончаются.
        if request.chunk ~= nil and #data >= request.chunk then
            return cut(data, request.chunk)
        end

        if #data > request.limit then
            return nil,
                data,
                ('строка длиннее %s байт: разделитель так и не пришёл'):format(
                    request.limit
                )
        end

        return nil, data
    end

    if request.chunk ~= nil and #data >= request.chunk then
        return cut(data, request.chunk)
    end

    return nil, data
end

return Module
