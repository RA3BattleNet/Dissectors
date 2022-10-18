GPCM_PORT = 29900
GpcmProtocol = Proto("gpcm", "Gamespy Presence Connection Manager")
GpcmProtocol.fields = {}
local gpcm_instances = {}
local tcp_stream_field = Field.new("tcp.stream")

function GpcmProtocol.init()
    gpcm_instances = {}
end

function GpcmProtocol.dissector(buffer, pinfo, tree)
    local stream_number = tcp_stream_field().value
    if not gpcm_instances[stream_number] then
        print("creating new gpcm instance with tcp stream number " .. stream_number)
        gpcm_instances[stream_number] = {
            server = GpcmMessages:new(),
            client = GpcmMessages:new(),
        }
    end
    local instance = gpcm_instances[stream_number]
    local is_to_server = pinfo.dst_port == GPCM_PORT
    local current_direction = instance.client
    if is_to_server then
        current_direction = instance.server
    end

    local length = buffer:len()
    if length == 0 then return end

    if not pinfo.visited then
        current_direction:insert(buffer, pinfo)
    end

    local current = current_direction.packets[pinfo.number]
    if not current then return end
    pinfo.cols.protocol = GpcmProtocol.name
    if current.info:len() == 0 then
        pinfo.columns.info = "GPCM Partial Data"
    else
        pinfo.columns.info = current.info
    end
    if not next(current.data) then return end

    local t = tree:add(GpcmProtocol, buffer())
    for i, message in ipairs(current.data) do
        -- a slice from packet tvb
        local tvb_range = buffer(message.index, message.length)
        -- try to create a field from message key
        local field = GpcmProtocol.fields[message.key]
        if not field then
            -- create a new field
            field = ProtoField.string("gpcm." .. message.key, message.key)
            GpcmProtocol.fields[message.key] = field
        end
        -- add the field to the tree
        local text = message.key
        if message.value:len() > 0 then
            text = text .. ": " .. message.value
        end
        t:add(field, tvb_range, text)
    end
end

GpcmMessages = {}

function GpcmMessages:new()
    local o = {
        previous = '',
        work_in_progress = {
            info = '',
            data = {}
        },
        packets = {}
    }
    setmetatable(o, self)
    self.__index = self
    return o
end

function GpcmMessages:insert(tvb, pinfo)
    if not self.packets[pinfo.number] then
        self.packets[pinfo.number] = { info = '', data = {} }
    end
    local current = self.packets[pinfo.number]
    local tvb_offset = -(self.previous:len()) -- zero based
    -- merge with unfinished content from previous packet
    local s = self.previous .. tvb:bytes():raw()
    local pattern = '\\([^\\]*)\\([^\\]*)'
    local i, j, key, value = s:find(pattern)
    while i do
        -- validate variable values
        if i ~= 1 then
            print('Warning: unexpected data before key-value pair: ' .. s:sub(1, j))
        end
        if key == nil then
            print('Warning: key is nil: ' .. s:sub(1, j))
            key = '<nil>'
        end
        if value == nil then
            print('Warning: value is nil: ' .. s:sub(1, j))
            value = '<nil>'
        end
        -- detect end of packet
        if key == 'final' then
            -- complete work_in_progress
            for k, v in ipairs(self.work_in_progress.data) do
                table.insert(current.data, v)
            end
            if current.info:len() > 0 then
                current.info = current.info .. "; "
            end
            current.info = current.info .. self.work_in_progress.info
            self.work_in_progress = {
                info = '',
                data = {}
            }
        else        
            -- work on current data
            local wip = self.work_in_progress
            -- format packet descrition
            if wip.info:len() > 0 then
                wip.info = wip.info .. ", "
            end
            wip.info = wip.info .. ('%s=%s'):format(key, value)
            -- advance offsets
            local current_tvb_offset = tvb_offset
            local current_length = j
            tvb_offset = tvb_offset + current_length
            -- if current message contains data from previous packet
            -- then current_tvb_offset will be negative
            -- in this case, index and length are indicative
            current_tvb_offset = math.max(current_tvb_offset, 0)
            current_length = math.max(tvb_offset, 0) - current_tvb_offset
            -- store index / length / data
            table.insert(wip.data, {
                index = current_tvb_offset,
                length = current_length,
                key = key,
                value = value
            })
        end
        -- remove processed data
        s = s:sub(j + 1)
        -- find next match
        i, j, key, value = s:find(pattern)
    end
    self.previous = s
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(GPCM_PORT, GpcmProtocol)