PEERCHAT_PORT = 6667
RA3_GAMEKEY = "uBZwpf"

PeerchatProtocol = Proto("peerchat", "Peerchat Protocol")
PeerchatProtocol.fields.payload = ProtoField.string("peerchat.payload", "Payload")
local peerchat_instances = {}
local tcp_stream_field = Field.new("tcp.stream")

function PeerchatProtocol.init()
    peerchat_instances = {}
    for k, v in ipairs(DissectorTable.list()) do
        print(v)
    end
end

function PeerchatProtocol.dissector(buffer, pinfo, tree)
    local stream_number = tcp_stream_field().value
    if not peerchat_instances[stream_number] then
        print("creating new peerchat instance with tcp stream number " .. stream_number)
        peerchat_instances[stream_number] = {
            server_cipher = PeerchatCipher:new(),
            client_cipher = PeerchatCipher:new(),
            decrypted_data = {},
            crypted = false
        }
    end
    local instance = peerchat_instances[stream_number]

    local length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = PeerchatProtocol.name

    local is_from_server = pinfo.src_port == PEERCHAT_PORT

    local t = tree:add(PeerchatProtocol, buffer())
    function add_to_wireshark(bytearray)
        local info = ""
        for s in bytearray:raw():gmatch("[^\r\n]+") do
            t:add(PeerchatProtocol.fields.payload, ByteArray.new(s, true):tvb("Payload")())
            if info:len() > 0 then info = info .. "; " end
            info = info .. s
        end
        pinfo.columns.info = info
    end

    if pinfo.visited then
        -- already processed, use cached data
        add_to_wireshark(instance.decrypted_data[pinfo.number])
        return
    end
    local data = buffer:bytes()
    instance.decrypted_data[pinfo.number] = data
    if instance.crypted then
        if is_from_server then
            instance.server_cipher:process(data)
        else
            instance.client_cipher:process(data)
        end
    end
    add_to_wireshark(data)

    if not instance.crypted and is_from_server then
        -- :s 705 * k|=voRElmbgHtKGW xwDplfMB>^lexB<r
        local payload = buffer():string()
        local i, j, client_key, server_key  = payload:find(":s 705 %* ([^ ]+) ([^ ]+)[\r\n]")
        if server_key and client_key then
            instance.server_cipher:initialize(server_key, RA3_GAMEKEY)
            instance.client_cipher:initialize(client_key, RA3_GAMEKEY)
            instance.crypted = true    
        end
        return
    end
end

PeerchatCipher = {}

function PeerchatCipher:new(o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
end

function PeerchatCipher:initialize(challenge, gamekey)
    self.pc1 = 0
    self.pc2 = 0

    local chall = {}
    -- lua string indices are 1-based
    for i = 1, challenge:len() do
        local challenge_byte = challenge:byte(i)
        local gamekey_byte = gamekey:byte((i - 1) % gamekey:len() + 1)
        -- however we will use 0-based indices
        chall[i - 1] = bit.bxor(challenge_byte, gamekey_byte)
    end
    self.table = {}
    for i = 0, 255 do
        self.table[i] = 255 - i
    end
    -- scramble up the table based on challenge
    local tmp = 0
    for i = 0, 255 do
        tmp = bit.band(tmp + chall[i % challenge:len()] + self.table[i], 0xFF)

        -- now just swap
        local tmp2 = self.table[tmp]
        self.table[tmp] = self.table[i]
        self.table[i] = tmp2
    end
end

function PeerchatCipher:process(bytearray)
    for i = 0, bytearray:len() - 1 do
        self.pc1 = bit.band(self.pc1 + 1, 0xFF)
        local tmp = self.table[self.pc1]
        self.pc2 = bit.band(self.pc2 + tmp, 0xFF)
        self.table[self.pc1] = self.table[self.pc2]
        self.table[self.pc2] = tmp
        tmp = bit.band(tmp + self.table[self.pc1], 0xFF)
        local datum = bytearray:get_index(i)
        datum = bit.bxor(datum, self.table[tmp])
        bytearray:set_index(i, datum)
    end
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(PEERCHAT_PORT, PeerchatProtocol)