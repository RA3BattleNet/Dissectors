QUERYMASTER_PORT = 28910
QueryMasterProtocol = Proto("querymaster", "QueryMaster Protocol")
QueryMasterProtocol.fields = {}
local querymaster_instances = {}
local tcp_stream_field = Field.new("tcp.stream")

function QueryMasterProtocol.init()
    querymaster_instances = {}
end

function QueryMasterProtocol.dissector(buffer, pinfo, tree)
    local stream_number = tcp_stream_field().value
    if not querymaster_instances[stream_number] then
        print("creating new querymaster instance with tcp stream number " .. stream_number)
        querymaster_instances[stream_number] = {
            server = { insert = function(x, y) end, packets = {} },
            client = QueryMasterClientRequest:new(),
        }
    end
    local instance = querymaster_instances[stream_number]
    local is_from_server = pinfo.src_port == QUERYMASTER_PORT
    local current_direction = instance.client
    if is_from_server then
        current_direction = instance.server
    end

    local length = buffer:len()
    if length == 0 then return end

    if not pinfo.visited then
        current_direction:insert(buffer, pinfo)
    end

    local current = current_direction.packets[pinfo.number]
    if not current then return end
    if not next(current.data) then return end

    pinfo.cols.protocol = QueryMasterProtocol.name
    pinfo.columns.info = current.info
    local t = tree:add(QueryMasterProtocol, buffer())
    for i, message in ipairs(current.data) do
        -- a slice from packet tvb
        local tvb_range = buffer(message.index, message.length)
        -- try to create a field from message key
        local field_key = ('%s.%s'):format(message.abbr, message.kind)
        local field = QueryMasterProtocol.fields[field_key]
        if not field then
            -- create a new field
            field = ProtoField[message.kind]("querymaster." .. message.abbr, message.key)
            QueryMasterProtocol.fields[field_key] = field
        end
        -- add the field to the tree
        local text = ('%s: %s'):format(message.key, message.value)
        t[message.action](t, field, tvb_range, text)
    end
end

QueryMasterClientRequest = {}

function QueryMasterClientRequest:new()
    local o = {
        previous = ByteArray.new(),
        packets = {}
    }
    setmetatable(o, self)
    self.__index = self
    return o
end

function QueryMasterClientRequest:insert(tvb, pinfo)
    if not self.packets[pinfo.number] then
        self.packets[pinfo.number] = { info = '', data = {} }
    end
    local current = self.packets[pinfo.number]
    current.info = 'QueryMaster Partial Request'
    -- merge with unfinished content from previous packet
    local bytes = self.previous .. tvb:bytes()
    -- we need at least 2 bytes so we can decode the length
    if bytes:len() < 2 then
        self.previous = bytes
        return
    end
    -- decode the length
    local message_length = bytes:get_index(0) * 256 + bytes:get_index(1)
    -- if packet is incomplete, save it for next packet
    if bytes:len() < message_length then
        self.previous = bytes
        return
    end
    local tvb_offset = -(self.previous:len()) -- zero based
    -- we have a complete packet, reset previous
    local remained_length = bytes:len() - message_length
    if remained_length > 0 then
        self.previous = bytes:subset(message_length, remained_length)
    else
        self.previous = ByteArray.new()
    end
    -- decode the packet
    local s = bytes:raw()
    local advance = function(size)
        tvb_offset = tvb_offset + size
        if (bytes:len() - size) > 0 then
            bytes = bytes:subset(size, bytes:len() - size)
            s = bytes:raw()
        else
            bytes = ByteArray.new()
            s = ''
        end
    end
    local insert = function(abbr, key, value, kind, size, little_endian)
        local message = {
            abbr = abbr,
            key = key,
            value = value,
            kind = kind,
            index = tvb_offset,
            length = size,
            action = 'add'
        }
        if little_endian then
            message.action = 'add_le'
        end
        table.insert(current.data, message)
        advance(size)
    end
    
    insert('length', 'Length', message_length, 'uint16', 2)
    local request_types = {
        [0] = 'SERVER_LIST_REQUEST',
        [1] = 'SERVER_INFO_REQUEST',
        [2] = 'SEND_MESSAGE_REQUEST',
        [3] = 'KEEPALIVE_REPLY',
        [4] = 'MAPLOOP_REQUEST',
        [5] = 'PLAYERSEARCH_REQUEST',
    }
    local request_type = request_types[bytes:get_index(0)] or '<INVALID>'
    insert('type', 'Type', request_type, 'string', 1)
    insert('protocol_version', 'List Protocol Version', bytes:get_index(0), 'uint8', 1)
    insert('encoding_version', 'List Encoding Version', bytes:get_index(0), 'uint8', 1)
    insert('game_version', 'Game Version', bytes:subset(0, 4):tvb('Game Version')():le_uint(), 'uint32', 4, true)
    local forgame = s:match('^([^\0]*)\0')
    insert('for_game', 'For Game Name', forgame, 'string', forgame:len() + 1)
    local fromgame = s:match('^([^\0]*)\0')
    insert('from_game', 'From Game Name', fromgame, 'string', fromgame:len() + 1)
    insert('challenge', 'Challenge', bytes:subset(0, 8):raw(), 'string', 8)
    local filter = s:match('^([^\0]*)\0')
    insert('filter', 'Filter', filter, 'string', filter:len() + 1)
    local fieldlist = s:match('^([^\0]*)\0')
    insert('fieldlist', 'Field List', fieldlist, 'string', fieldlist:len() + 1)
    local options = bytes:subset(0, 4)
    insert('options', 'Options', options:tohex(), 'uint32', 4, true)
    if bit.band(options:get_index(3), 0x08) ~= 0 then
        local raw_ip = bytes:subset(0, 4)
        local ip = Address.ip(('%d.%d.%d.%d'):format(raw_ip:get_index(0), raw_ip:get_index(1), raw_ip:get_index(2), raw_ip:get_index(3)))
        insert('ip', 'IP', ip, 'ipv4', 4)
    end
    if bit.band(options:get_index(3), 0x80) ~= 0 then
        local raw_limit = bytes:subset(0, 4)
        local limit = raw_limit:get_index(3)
        limit = limit * 256 + raw_limit:get_index(2)
        limit = limit * 256 + raw_limit:get_index(1)
        limit = limit * 256 + raw_limit:get_index(0)
        insert('max_servers', 'Max Servers', limit, 'uint32', 4)
    end
    current.info = ('%s %s'):format(request_type, fieldlist)
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(QUERYMASTER_PORT, QueryMasterProtocol)