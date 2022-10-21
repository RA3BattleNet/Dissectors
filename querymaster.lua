QUERYMASTER_PORT = 28910
RA3_GAMEKEY = "uBZwpf"

QueryMasterProtocol = Proto("querymaster", "QueryMaster Protocol")
QueryMasterProtocol.fields = {}
local querymaster_instances = {}
local tcp_stream_field = Field.new("tcp.stream")
local parse_state_field = ProtoField.string("querymaster.parse_state", "ParseState")

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
    function add_to_tree(prefix, t, message)
        -- try to create a field from message key
        local full_abbr = ('%s.%s'):format(prefix, message.abbr)
        local field_key = ('%s/%s'):format(full_abbr, message.kind)
        local field = QueryMasterProtocol.fields[field_key]
        if not field then
            -- create a new field
            field = ProtoField[message.kind](full_abbr, message.key)
            QueryMasterProtocol.fields[field_key] = field
        end

        local text = ('%s: %s'):format(message.key, message.value)
        local tvb_range = packet_tvb_range
        if not current.is_from_server then
            -- a slice from packet tvb
            tvb_range = buffer(message.index, message.length)
        end
        -- add the field to the tree
        t[message.action or 'add'](t, field, tvb_range, text)
    end
    local t = tree:add(QueryMasterProtocol, packet_tvb_range)
    if current.is_from_server then
        packet_tvb_range = current.raw:tvb('Raw Data')()
        local value = ('<Parse State: %s>'):format(instance.server.parse_state)
        t:add(parse_state_field, packet_tvb_range, value)
    end
    for i, message in ipairs(current.data) do
        add_to_tree('querymaster', t, message)
    end
    if next(current.servers or {}) then
        for i, server_data in ipairs(current.servers) do
            local subtree = t:add(QueryMasterProtocol, packet_tvb_range, 'Server')
            for j, field in ipairs(server_data) do
                add_to_tree('querymaster.server', subtree, field)
            end
        end
    end
    if next(current.ad_hoc_data or {}) then
        local subtree = t:add(QueryMasterProtocol, packet_tvb_range, 'Ad Hoc Data')
        for i, field in ipairs(current.ad_hoc_data) do
            add_to_tree('querymaster.ad_hoc_data', subtree, field)
        end
    end
end

local bytearray_to_ip = function(bytearray)
    local a, b = bytearray:get_index(0), bytearray:get_index(1)
    local c, d = bytearray:get_index(2), bytearray:get_index(3)
    return Address.ip(('%d.%d.%d.%d'):format(a, b, c, d))
end

local bytearray_to_net16 = function(bytearray)
    local a, b = bytearray:get_index(0), bytearray:get_index(1)
    return a * 256 + b
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
    local message_length = bytearray_to_net16(bytes)
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
local KeyType = {
    BYTE = 1,
    UINT16 = 2,
    STRING = 0
}
local KeyTypeToString = (function()
    local t = {}
    for k, v in pairs(KeyType) do
        t[v] = k:lower()
    end
    return t
end)()

local ResponseType = {
    PUSH_KEYS_MESSAGE = 1,
    PUSH_SERVER_MESSAGE = 2,
    KEEPALIVE_MESSAGE = 3,
    DELETE_SERVER_MESSAGE = 4,
    MAPLOOP_MESSAGE = 5,
    PLAYERSEARCH_MESSAGE = 6,
}
local ResponseTypeToString = (function()
    local t = {}
    for k, v in pairs(ResponseType) do
        t[v] = k
    end
    return t
end)()

function QueryMasterServerResponse:new()
    local o = {
        parse_state = 'CRYPT_HEADER',
        unparsed = ByteArray.new(),
        packets = {},
        keys = {},
        popular_values = {},
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
                })
            end,
            store_raw = function(self, bytes, count)
                self.raw = self.raw .. bytes:subset(0, count)
            end,
            servers = {},
            ad_hoc_data = {}
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
    elseif self.parse_state == 'FINISHED' then
        self:handle_ad_hoc_data(current)
    end

    if next(current.servers) then
        current.info = 'QueryMasterResponse ServerList'
    end
    if next(current.ad_hoc_data) then
        current.info = current.info .. '& QueryMaster AdHocData'
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
    local port = bytearray_to_net16(self.unparsed:subset(4, 2))
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
        local type_as_string = KeyTypeToString[key_type] or '<INVALID>'
        local description = ('%s => %s'):format(key_name, type_as_string)
        current:push_data('declared_field', 'Declared field', description, 'string')
        table.insert(self.keys, {
            key_type = key_type,
            key_name = key_name,
        })
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
        table.insert(self.popular_values, value)
    end
    -- continue parsing
    self.parse_state = 'SERVERS'
    self:handle_servers(current)
end

function QueryMasterServerResponse:handle_servers(current)
    local size_modifiers = {
        PRIVATE_IP_FLAG = { value = 2, size_modifier = 4 },
        ICMP_IP_FLAG = { value = 8, size_modifier = 4 },
        NON_STANDARD_PORT_FLAG = { value = 16, size_modifier = 2 },
        NON_STANDARD_PRIVATE_PORT_FLAG = { value = 32, size_modifier = 2 },
    }
    while self.unparsed:len() > 0 do
        local flag = self.unparsed:get_index(0)
        local length = 5
        local flag_values = {
            non_standard_port = false,
            private_ip = false,
            non_standard_private_port = false,
            icmp_ip = false,
        }
        for k, v in pairs(size_modifiers) do
            if bit.band(flag, v.value) ~= 0 then
                length = length + v.size_modifier
                local flag_name = k:match('^(.*)_FLAG$'):lower()
                flag_values[flag_name] = true
            end
        end
        if self.unparsed:len() < length then
            -- no enough data
            return
        end
        -- check if finished
        local LAST_SERVER_MARKER = ByteArray.new('FFFFFFFF')
        if self.unparsed:subset(1, 4) == LAST_SERVER_MARKER then
            -- finished!
            current:store_raw(self.unparsed, 5)
            self:advance_unparsed_buffer(5)
            self.parse_state = 'FINISHED'
            return
        end
        -- start parsing
        local local_parse_context = {
            -- parameters
            use_popular_values = true,
            -- flag values
            flag = flag,
            flag_values = flag_values,
            -- parse buffer
            parsed_length = 1,
            unparsed = self.unparsed:subset(1, self.unparsed:len() - 1),
            advance_unparsed = function(self, length)
                local remained_length = self.unparsed:len() - length
                if remained_length > 0 then
                    self.unparsed = self.unparsed:subset(length, remained_length)
                elseif remained_length == 0 then
                    self.unparsed = ByteArray.new()
                else
                    throw_error('QueryMasterServerResponse advance_unparsed out of range')
                end
                self.parsed_length = self.parsed_length + length
            end,
            -- parsed data
            fields = {},
            push_data = function(self, abbr, key, value, kind)
                local field = {
                    abbr = abbr,
                    key = key,
                    value = value,
                    kind = kind,
                }
                table.insert(self.fields, field)
            end,
        }
        local_parse_context:push_data('flag', 'Flag', ('%02X'):format(flag), 'uint8')
        -- parse server ip port
        local public_ip = bytearray_to_ip(local_parse_context.unparsed)
        local_parse_context:push_data('public_ip', 'Public IP', public_ip, 'ipv4')
        local_parse_context:advance_unparsed(4)
        if flag_values.non_standard_port then
            local public_port = bytearray_to_net16(local_parse_context.unparsed)
            local_parse_context:push_data('public_port', 'Public Port', public_port, 'uint16')
            local_parse_context:advance_unparsed(2)
        end
        -- parse server body
        local server = self:parse_server_body(local_parse_context)
        if not server then
            -- need more data
            return
        end
        -- store parsed data for this server
        table.insert(current.servers, local_parse_context.fields)
        -- store parsed raw data
        current:store_raw(self.unparsed, local_parse_context.parsed_length)
        -- consume parsed length
        self:advance_unparsed_buffer(local_parse_context.parsed_length)
    end
end

function QueryMasterServerResponse:handle_ad_hoc_data(current)
    -- process as long as there is enough data
    while self.unparsed:len() >= 3 do
        local length = bytearray_to_net16(self.unparsed)
        if self.unparsed:len() < length then
            -- no enough data
            return
        end
        local message_type = ResponseTypeToString[self.unparsed:get_index(2)]
            or '<INVALID>'
        local rawhex = self.unparsed:subset(0, length):tohex()
        table.insert(current.ad_hoc_data, {
            abbr = 'message_type',
            key = 'Message Type',
            value = message_type,
            kind = 'byte',
        })
        table.insert(current.ad_hoc_data, {
            abbr = 'raw',
            key = 'Raw',
            value = rawhex,
            kind = 'string',
        })
        -- store raw data
        current:store_raw(self.unparsed, length)
        -- consume parsed length
        self:advance_unparsed_buffer(length)
        -- TODO: handle ad hoc data
    end
end

function QueryMasterServerResponse:parse_server_body(context)
    if type(context.use_popular_values) ~= 'boolean' then
        throw_error('QueryMasterServerResponse parse_server_body: '
            .. 'use_popular_values must be boolean')
    end
    -- parse private ip and port
    if context.flag_values.private_ip then
        local private_ip = bytearray_to_ip(context.unparsed)
        context:push_data('private_ip', 'Private IP', private_ip, 'ipv4')
        context:advance_unparsed(4)
    end
    if context.flag_values.non_standard_private_port then
        local private_port = bytearray_to_net16(context.unparsed)
        context:push_data('private_port', 'Private Port', private_port, 'uint16')
        context:advance_unparsed(2)
    end
    -- parse icmp ip
    if context.flag_values.icmp_ip then
        local icmp_ip = bytearray_to_ip(context.unparsed)
        context:push_data('icmp_ip', 'ICMP IP', icmp_ip, 'ipv4')
        context:advance_unparsed(4)
    end
    -- parse keys
    local HAS_KEYS_FLAG = 64
    if bit.band(context.flag, HAS_KEYS_FLAG) ~= 0 then
        for i, key in ipairs(self.keys) do
            local type_name = KeyTypeToString[key.key_type]
            if key.key_type == KeyType.BYTE then
                if context.unparsed:len() < 1 then
                    -- need more data
                    return nil
                end
                local value = context.unparsed:get_index(0)
                context:push_data(key.key_name, key.key_name, value, type_name)
                context:advance_unparsed(1)
            elseif key.key_type == KeyType.UINT16 then
                if context.unparsed:len() < 2 then
                    -- need more data
                    return nil
                end
                local value = bytearray_to_net16(context.unparsed)
                context:push_data(key.key_name, key.key_name, value, type_name)
                context:advance_unparsed(2)
            elseif key.key_type == KeyType.STRING then
                local popular_index = 0xFF
                if context.use_popular_values then
                    if context.unparsed:len() < 1 then
                        -- need more data
                        return nil
                    end
                    popular_index = context.unparsed:get_index(0)
                    context:advance_unparsed(1)
                end
                if popular_index == 0xFF then
                    -- null terminated string
                    local string = context.unparsed:raw():match('^([^\0]*)\0')
                    if string == nil then
                        -- need more data
                        return nil
                    end
                    context:push_data(key.key_name, key.key_name, string, type_name)
                    context:advance_unparsed(string:len() + 1)
                else
                    -- lua table is 1 based
                    local string = self.popular_values[popular_index + 1]
                    context:push_data(key.key_name, key.key_name, string, type_name)
                end
            end
        end
    end
    -- parse rules
    local HAS_FULL_RULES_FLAG = 128
    if bit.band(context.flag, HAS_FULL_RULES_FLAG) ~= 0 then
        while context.unparsed:len() > 0 do
            if context.unparsed:get_index(0) == 0 then
                -- end of rules
                context:advance_unparsed(1)
                break
            end
            local rule_name = context.unparsed:raw():match('^([^\0]*)\0')
            if rule_name == nil then
                -- need more data
                return nil
            end
            context:advance_unparsed(rule_name:len() + 1)
            local rule_value = context.unparsed:raw():match('^([^\0]*)\0')
            if rule_value == nil then
                -- need more data
                return nil
            end
            context:advance_unparsed(rule_value:len() + 1)
            context:push_data(rule_name, rule_name, rule_value, 'string')
        end
    end
    return true
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