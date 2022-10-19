QUERYMASTER_PORT = 28910
RA3_GAMEKEY = "uBZwpf"

QueryMasterProtocol = Proto("querymaster", "QueryMaster Protocol")
QueryMasterProtocol.fields = {}
local querymaster_instances = {}
local tcp_stream_field = Field.new("tcp.stream")

local throw_error = function(what)
    error(what)
end

local dissector = function(buffer, pinfo, tree)
    local stream_number = tcp_stream_field().value
    if not querymaster_instances[stream_number] then
        print("creating new querymaster instance with tcp stream number " .. stream_number)
        querymaster_instances[stream_number] = {
            server = QueryMasterServerResponse:new(),
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
        if not is_from_server then
            -- if the current direction is client
            -- then we might retrieve challenge and options from client's request
            -- which is used by server's response
            if current_direction.challenge then
                instance.server:set_cipher_challenge(current_direction.challenge)
            end
            if current_direction.no_server_list then
                instance.server:set_no_server_list(current_direction.no_server_list)
            end
        end
    end

    local current = current_direction.packets[pinfo.number]
    if not current then return end
    if not next(current.data) then return end

    pinfo.cols.protocol = QueryMasterProtocol.name
    pinfo.columns.info = current.info
    local packet_tvb_range = buffer()
    if current.is_from_server then
        packet_tvb_range = current.raw:tvb('Raw Data')()
    end
    local t = tree:add(QueryMasterProtocol, packet_tvb_range)
    for i, message in ipairs(current.data) do
        -- try to create a field from message key
        local field_key = ('%s.%s'):format(message.abbr, message.kind)
        local field = QueryMasterProtocol.fields[field_key]
        if not field then
            -- create a new field
            field = ProtoField[message.kind]("querymaster." .. message.abbr, message.key)
            QueryMasterProtocol.fields[field_key] = field
        end

        local text = ('%s: %s'):format(message.key, message.value)
        local tvb_range = packet_tvb_range
        if not current.is_from_server then
            -- a slice from packet tvb
            tvb_range = buffer(message.index, message.length)
        end
        -- add the field to the tree
        t[message.action](t, field, tvb_range, text)
    end
end

local bytearray_to_ip = function(bytearray)
    local a, b = bytearray:get_index(0), bytearray:get_index(1)
    local c, d = bytearray:get_index(2), bytearray:get_index(3)
    return Address.ip(('%d.%d.%d.%d'):format(a, b, c, d))
end

function QueryMasterProtocol.init()
    querymaster_instances = {}
end

function QueryMasterProtocol.dissector(buffer, pinfo, tree)
    local status, error = pcall(dissector, buffer, pinfo, tree)
    if not status then
        print(('caught error on packet number %d: '):format(pinfo.number))
        print(tostring(error))
    end
end

QueryMasterClientRequest = {}

function QueryMasterClientRequest:new()
    local o = {
        previous = ByteArray.new(),
        challenge = nil,
        no_server_list = nil,
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
    self.challenge = bytes:subset(0, 8)
    insert('challenge', 'Challenge', self.challenge:raw(), 'string', 8)
    local filter = s:match('^([^\0]*)\0')
    insert('filter', 'Filter', filter, 'string', filter:len() + 1)
    local fieldlist = s:match('^([^\0]*)\0')
    insert('fieldlist', 'Field List', fieldlist, 'string', fieldlist:len() + 1)
    local options = bytes:subset(0, 4)
    insert('options', 'Options', options:tohex(), 'uint32', 4, true)
    if bit.band(options:get_index(3), 0x02) ~= 0 then
        insert('no_server_list', 'No Server List', 'true', 'string', 0)
        self.no_server_list = true
    end
    if bit.band(options:get_index(3), 0x08) ~= 0 then
        insert('ip', 'IP', bytearray_to_ip(bytes), 'ipv4', 4)
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

QueryMasterServerResponse = {}
--[[
local SBListParseState = {
    [0] = 'CRYPT_HEADER',
    [1] = 'FIXED_HEADER',
    [2] = 'KEY_LIST',
    [3] = 'UNIQUE_VALUE_LIST',
    [4] = 'SERVERS',
    [5] = 'FINISHED'
}
]]--

function QueryMasterServerResponse:new()
    local o = {
        parse_state = 'CRYPT_HEADER',
        unparsed = ByteArray.new(),
        packets = {}
    }
    setmetatable(o, self)
    self.__index = self
    return o
end

function QueryMasterServerResponse:set_cipher_challenge(bytearray)
    if self.challenge then
        throw_error('QueryMasterServerResponse Challenge already set')
    end
    if bytearray:len() ~= 8 then
        throw_error('QueryMasterServerResponse Invalid challenge length')
    end
    self.challenge = bytearray
end

function QueryMasterServerResponse:set_no_server_list(value)
    self.no_server_list = value
end

function QueryMasterServerResponse:insert(tvb, pinfo)
    if not self.packets[pinfo.number] then
        self.packets[pinfo.number] = {
            is_from_server = true,
            info = 'QueryMasterServerResponse Partial Data',
            data = {},
            raw = ByteArray.new(),
            push_data = function(self, abbr, key, value, kind)
                table.insert(self.data, {
                    abbr = abbr,
                    key = key,
                    value = value,
                    kind = kind,
                    action = 'add'
                })
            end,
            store_raw = function(self, bytes, count)
                self.raw = self.raw .. bytes:subset(0, count)
            end
        }
    end
    local current = self.packets[pinfo.number]
    current.info = 'QueryMaster Partial Response'
    -- merge with unfinished content from previous packet
    if self.parse_state ~= 'CRYPT_HEADER' then
        if not self.cipher then
            throw_error('QueryMasterServerResponse No cipher found')
            return
        end
        self.unparsed = self.unparsed .. self.cipher:decrypt(tvb:bytes())
    else
        self.unparsed = self.unparsed .. tvb:bytes()
    end

    if self.parse_state == 'CRYPT_HEADER' then
        self:handle_crypt_header(current)
    elseif self.parse_state == 'FIXED_HEADER' then
        self:handle_fixed_header(current)
    elseif self.parse_state == 'KEY_LIST' then
        self:handle_key_list(current)
    elseif self.parse_state == 'UNIQUE_VALUE_LIST' then
        self:handle_unique_value_list(current)
    elseif self.parse_state == 'SERVERS' then
        self:handle_servers(current)
    end
end

function QueryMasterServerResponse:handle_crypt_header(current)
    if self.unparsed:len() < 1 then
        -- no enough data
        return
    end
    local request_length = self.unparsed:get_index(0)
    request_length = bit.bxor(request_length, 0xEC) + 2
    if self.unparsed:len() < request_length then
        -- no enough data
        return
    end
    local key_offset = request_length
    local key_length = self.unparsed:get_index(request_length - 1)
    key_length = bit.bxor(key_length, 0xEA)
    request_length = request_length + key_length
    if self.unparsed:len() < request_length then
        -- no enough data
        return
    end
    -- initialize cipher
    if not self.challenge then
        throw_error('QueryMasterServerResponse Challenge not set')
        return
    end
    local serverkey = self.unparsed:subset(key_offset, key_length)
    local gamekey = ByteArray.new(RA3_GAMEKEY, true)
    for i = 0, serverkey:len() - 1 do
        local value = self.challenge:get_index(i % self.challenge:len())
        value = bit.bxor(value, serverkey:get_index(i))
        local index = (i * gamekey:get_index(i % gamekey:len())) % self.challenge:len()
        value = bit.bxor(value, self.challenge:get_index(index))
        self.challenge:set_index(index, value)
    end
    self.cipher = EncTypeX:new()
    self.cipher:initialize(self.challenge, self.challenge:len())
    -- parse backed game flags
    local backend_game_flags = self.unparsed:subset(1, 2):tohex()
    current:push_data('backend_game_flags', 'Backend Game Flags', backend_game_flags, 'uint16')
    -- store raw data
    current:store_raw(self.unparsed, request_length)
    -- decrypt remaining data
    self:advance_unparsed_buffer(request_length)
    self.unparsed = self.cipher:decrypt(self.unparsed)
    -- continue parsing
    self.parse_state = 'FIXED_HEADER'
    self:handle_fixed_header(current)
end

function QueryMasterServerResponse:handle_fixed_header(current)
    local fixed_header_length = 6 -- ip and port
    if self.unparsed:len() < fixed_header_length then
        -- no enough data
        return
    end
    local ip = bytearray_to_ip(self.unparsed)
    local port = self.unparsed:get_index(4) * 256 + self.unparsed:get_index(5)
    if port == 0xFFFF then
        current.info = 'QueryMaster Error'
        -- error: try get error string
        local match_position = fixed_header_length + 1 -- lua string index is 1 based
        local reason = self.unparsed:raw():match('^([^\0]*)\0', fixed_header_length)
        if not reason then
            -- need more data
            return
        end
        current:store_raw(self.unparsed, self.unparsed:len())
        self:advance_unparsed_buffer(fixed_header_length + reason:len() + 1)
        current.info = ('QueryMaster Error: %s'):format(reason)
        current:push_data('error', 'Error', reason, 'string')
        self.parse_state = 'FINISHED'
        return
    end
    current:store_raw(self.unparsed, fixed_header_length)
    self:advance_unparsed_buffer(fixed_header_length)
    current.info = ('IP %s:%d'):format(ip, port)
    current:push_data('ip', 'IP', ip, 'ipv4')
    current:push_data('port', 'Port', port, 'uint16')
    if self.no_server_list then
        self.parse_state = 'FINISHED'
        return
    end
    -- continue parsing
    self.expected_elements = nil
    self.parse_state = 'KEY_LIST'
    self:handle_key_list(current)
end

function QueryMasterServerResponse:handle_key_list(current)
    if not self.expected_elements then
        if self.unparsed:len() < 1 then
            -- no enough data
            return
        end
        self.expected_elements = self.unparsed:get_index(0)
        current:store_raw(self.unparsed, 1)
        self:advance_unparsed_buffer(1)
    end
    while self.expected_elements > 0 do
        if self.unparsed:len() < 2 then
            -- no enough data
            return
        end
        local key_type = self.unparsed:get_index(0)
        local key_name = self.unparsed:raw(1):match('^([^\0]*)\0')
        if not key_name then
            -- need more data
            return
        end
        current:store_raw(self.unparsed, 1 + key_name:len() + 1)
        self:advance_unparsed_buffer(1 + key_name:len() + 1)
        self.expected_elements = self.expected_elements - 1
        local key_abbr = ('key_0x%X'):format(key_type)
        local key_label = ('Key 0x%X'):format(key_type)
        current:push_data(key_abbr, key_label, key_name, 'string')
    end
    -- continue parsing
    self.expected_elements = nil
    self.parse_state = 'UNIQUE_VALUE_LIST'
    self:handle_unique_value_list(current)
end

function QueryMasterServerResponse:handle_unique_value_list(current)
    if not self.expected_elements then
        if self.unparsed:len() < 1 then
            -- no enough data
            return
        end
        self.expected_elements = self.unparsed:get_index(0)
        current:store_raw(self.unparsed, 1)
        self:advance_unparsed_buffer(1)
    end
    while self.expected_elements > 0 do
        local value = self.unparsed:raw():match('^([^\0]*)\0')
        if not value_name then
            -- need more data
            return
        end
        current:store_raw(self.unparsed, value_name:len() + 1)
        self:advance_unparsed_buffer(value_name:len() + 1)
        self.expected_elements = self.expected_elements - 1
        current:push_data('unique_value', 'Unique Value', value, 'string')
    end
    -- continue parsing
    self.parse_state = 'SERVERS'
    self:handle_servers(current)
end

function QueryMasterServerResponse:handle_servers(current)
    -- todo: implement parse server
    current:store_raw(self.unparsed, self.unparsed:len())
    local data = self.unparsed:raw()
    self:advance_unparsed_buffer(data:len())
    current:push_data('server_raw', 'Server Raw data', data, 'string')
end

function QueryMasterServerResponse:advance_unparsed_buffer(length)
    local remained_length = self.unparsed:len() - length
    if remained_length > 0 then
        self.unparsed = self.unparsed:subset(length, remained_length)
    elseif remained_length == 0 then
        self.unparsed = ByteArray.new()
    else
        throw_error('QueryMasterServerResponse advance_unparsed_buffer out of range')
    end
end

-- https://github.com/nitrocaster/GameSpy/blob/master/src/GameSpy/serverbrowsing/sb_crypt.c
EncTypeX = {}

function EncTypeX:new()
    local o = {
        cards = {},
        rotor = 1,
        ratchet = 3,
        avalanche = 5,
        last_plain = 7,
        last_cipher = 11,
    }
    for i = 0, 255 do
        o.cards[i] = 255 - i
    end
    setmetatable(o, self)
    self.__index = self
    return o
end

function EncTypeX:initialize(key, keysize)
    for i = 0, 255 do
        self.cards[i] = i
    end
    local toswap = 0
    local keypos = 0
    local rsum = 0
    local keyrand = function(i)
        if i == 0 then
            return 0
        end
        local retry_limiter = 0
        local mask = 1
        while mask < i do
            mask = mask * 2 + 1
        end
        local u
        repeat
            rsum = (self.cards[rsum] + key:get_index(keypos)) % 256
            keypos = keypos + 1
            if keypos >= keysize then
                keypos = 0
                rsum = (rsum + keysize) % 256
            end
            u = bit.band(mask, rsum)
            retry_limiter = retry_limiter + 1
            if retry_limiter > 11 then
                u = u % i
            end
        until u <= i
        return u % 256
    end
    for i = 255, 0, -1 do
        toswap = keyrand(i)
        self.cards[i], self.cards[toswap] = self.cards[toswap], self.cards[i]
    end
    self.rotor = self.cards[1]
    self.ratchet = self.cards[3]
    self.avalanche = self.cards[5]
    self.last_plain = self.cards[7]
    self.last_cipher = self.cards[rsum]
end

function EncTypeX:decrypt_byte(byte)
    byte = byte % 256

    self.ratchet = (self.ratchet + self.cards[self.rotor]) % 256
    self.rotor = (self.rotor + 1) % 256
    local temp = self.cards[self.last_cipher]
    self.cards[self.last_cipher] = self.cards[self.ratchet]
    self.cards[self.ratchet] = self.cards[self.last_plain]
    self.cards[self.last_plain] = self.cards[self.rotor]
    self.cards[self.rotor] = temp
    self.avalanche = (self.avalanche + self.cards[temp]) % 256

    local index_1 = (self.cards[self.avalanche] + self.cards[self.rotor]) % 256
    local index_nested = (self.cards[self.last_plain]
        + self.cards[self.last_cipher]
        + self.cards[self.ratchet]) % 256
    local index_2 = self.cards[index_nested] % 256
    local new_plain = bit.bxor(byte, self.cards[index_1])
    new_plain = bit.bxor(new_plain, self.cards[index_2])
    self.last_plain = new_plain % 256
    self.last_cipher = byte
    return self.last_plain
end

function EncTypeX:decrypt(bytearray)
    local result = ByteArray.new(bytearray:raw(), true)
    for i = 0, bytearray:len() - 1 do
        result:set_index(i, self:decrypt_byte(bytearray:get_index(i)))
    end
    return result
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(QUERYMASTER_PORT, QueryMasterProtocol)