-- Persistent registration, with explicit expiring call requests; never arms a trunk.
package.path = "/opt/?.lua;" .. package.path
local net = require("net")
local sip = require("sip")
local cfg = require("ims.cfg")
local ue = require("ims.ue")
local sipio = require("ims.sipio")
local regflow = require("ims.regflow")
local register = require("ims.register")
local wire = require("ims.wire")
-- Match the actual socket transport during REGISTER contact promotion.
wire.contact = function(sub)
    return "<sip:" .. wire.ue_at(sub) .. ";transport=udp>"
end

assert(cfg.nsubs == 1 and cfg.require_ipsec and not cfg.verbose and not cfg.dump,
       "one subscriber, IPsec, and disabled credential logging are mandatory")
local state_dir = os.getenv("DPT_REG_STATE") or "/run/dpt-registration"
local msisdn = assert(os.getenv("IMS_MSISDN"), "lab MSISDN required"):gsub("^%+", "")
assert(msisdn:match("^%d+$") and #msisdn <= 15, "invalid MSISDN")
local pcscf = assert(os.getenv("PCSCF_IP"), "P-CSCF required")
local interface = os.getenv("IMS_UE_IFACE") or "uesimtun1"
local renewal_limit = tonumber(os.getenv("IMS_RENEW_SECONDS") or "240")
assert(renewal_limit and renewal_limit >= 10 and renewal_limit <= 300,
       "renewal interval must be 10..300 seconds")
local random = assert(io.open("/dev/urandom", "rb"))
local entropy = assert(random:read(12)); random:close()
local boot = (entropy:gsub(".", function(c) return ("%02x"):format(c:byte()) end))
cfg.spi_base = 256 + ((entropy:byte(1) * 16777216 + entropy:byte(2) * 65536
                   + entropy:byte(3) * 256 + entropy:byte(4)) % 1073741568)

-- The upstream example uses deterministic boot identifiers. Keep its codec and
-- AKA implementation, but avoid proxy transaction-cache collisions after reboot.
local original_build = register.build
register.build = function(sub, ...)
    local bytes = original_build(sub, ...)
    bytes = bytes:gsub("(\r\nCall%-ID: )[^\r\n]+", "%1" .. boot .. "@" .. sub.ue_addr, 1)
    bytes = bytes:gsub("(branch=z9hG4bK%-)", "%1" .. boot .. "-", 1)
    return bytes
end

local state = {state = "starting", registered = false, imsi = cfg.base_imsi,
    msisdn = msisdn, realm = cfg.realm, renewals = 0, expires_at = 0,
    msisdn_associated = false, protected = false}
local function quote(s)
    return '"' .. tostring(s):gsub('[%z\1-\31\\"]', function(c)
        return ("\\u%04x"):format(c:byte())
    end) .. '"'
end
local function write_status(name, values)
    local fields = {}
    for key, value in pairs(values) do
        fields[#fields + 1] = quote(key) .. ":" ..
            (type(value) == "string" and quote(value) or tostring(value))
    end
    local file = assert(io.open(state_dir .. "/" .. name .. ".tmp", "w"))
    file:write("{" .. table.concat(fields, ",") .. "}\n"); file:close()
    assert(os.rename(state_dir .. "/" .. name .. ".tmp", state_dir .. "/" .. name .. ".json"))
end
local function publish()
    state.updated_at = os.time()
    write_status("status", state)
end
local function exists(name)
    local file = io.open(state_dir .. "/" .. name, "r")
    if file then file:close(); return true end
    return false
end
publish()
local address
for _ = 1, 30 do
    local ok, value = pcall(net.if_addr4, interface)
    if ok and value and value ~= "" then address = value; break end
    if exists("stop") then state.state = "stopped"; publish(); os.exit(0) end
    os.execute("sleep 1")
end
if not address then
    state.state = "waiting-for-ims-tunnel"; publish(); os.exit(1)
end
state.address = address
local loop = net.Loop()
local sub = ue.new(1)
sub.ue_addr, sub.pcscf = address, pcscf
local stats = {tx = 0, rx = 0, regs = 0, protected = 0, sa_fail = 0, latency = {}}
local io_ = sipio.new(stats)
local flow, renew_timer, stopping, failed, active_call, active_request_id

local function stop(reason, failure)
    if stopping then return end
    stopping, failed = true, failure
    if active_call and active_call.state ~= "done" then active_call.stop() end
    if renew_timer then loop:cancel(renew_timer) end
    flow.disarm(sub)
    flow.deregister()
    state.registered, state.state = false, reason
    publish()
    loop:after(1500, function() loop:stop() end)
end
local function renew()
    if renew_timer then pcall(function() loop:cancel(renew_timer) end) end
    renew_timer = nil
    if stopping or sub.restoring then return end
    if active_call and active_call.state ~= "done" then
        renew_timer = loop:after(5000, renew)
        return
    end
    state.state, state.registered = "renewing", false
    publish()
    -- A fresh authenticated initial registration and fresh SPIs are used.
    -- Do not reuse an old nonce-count/digest as if it were a new refresh.
    if not flow.restore(sub, "scheduled registration renewal") then
        stop("renewal-start-failed", true)
    end
end
local function confirmed(_, m)
    local associated = false
    for _, identity in ipairs(sub.assoc or {}) do
        if wire.same_id(identity, "tel:+" .. msisdn)
           or wire.same_id(identity, "sip:" .. msisdn .. "@" .. cfg.realm) then
            associated = true
        end
    end
    assert(associated and sub.protected, "MSISDN association over IPsec required")
    local expires = tonumber(m:header("Contact"):match(";expires=(%d+)"))
                    or tonumber(m:header("Expires"))
    assert(expires and expires >= 20, "explicit positive granted lease required")
    state.state, state.registered, state.protected = "registered", true, true
    state.msisdn_associated = true
    state.last_registered_at = os.time()
    state.expires_at = state.last_registered_at + expires
    state.service_routes = #(sub.svc_route or {})
    state.pcscf_server_spi = sub.ch.p_spi_s
    state.pcscf_client_spi = sub.ch.p_spi_c
    state.pcscf_server_port = sub.ch.p_port_s
    state.pcscf_client_port = sub.ch.p_port_c
    state.ue_client_spi = sub.spi_uc
    state.ue_server_spi = sub.spi_us
    local contact = wire.contact_uri(m)
    if contact then sub.registered_contact = "<" .. contact .. ">" end
    assert(state.service_routes > 0, "Service-Route required")
    local delay = math.max(10, math.min(renewal_limit, math.floor(expires / 2)))
    state.next_renewal_at = os.time() + delay
    if renew_timer then loop:cancel(renew_timer) end
    renew_timer = loop:after(delay * 1000, renew)
    publish()
    print("DPT_REGISTRATION confirmed; MSISDN associated; IPsec; lease=" .. expires)
end
flow = regflow.new{
    loop = loop, io = io_, stats = stats, subs = {sub}, on_registered = confirmed,
    on_terminal = function()
        sub.done = true
        flow.disarm(sub)
        if not sub.registered then stop("registration-failed", true) end
    end,
    on_restored = function(_, ok)
        if not ok then return stop("renewal-failed", true) end
        state.renewals = state.renewals + 1
        publish()
    end,
}
local function message(_, m, dg)
    if active_call and active_call.handle(m) then return end
    if m.request then
        if dg.host ~= pcscf then return end
        local accepted = m.method == sip.OPTIONS or m.method == sip.NOTIFY
        io_.send(sub, "mt", wire.response(sub, m, {
            status = accepted and 200 or 480,
            reason = accepted and "OK" or "Temporarily Unavailable",
            to_tag = boot,
        }), "registration-only response")
    else
        flow.handle(sub, m)
    end
end
local function call_request()
    local file = io.open(state_dir .. "/call-request", "r")
    if not file then return end
    local request = file:read("*a"); file:close(); os.remove(state_dir .. "/call-request")
    local id, destination, expiry = request:match("^([a-f0-9]+)\n(%+[1-9]%d+)\n(%d+)\n$")
    local report = {request_id = id or "", state = "rejected", updated_at = os.time(),
                    answered = false, final_status = 0, release_ok = false}
    if not id or #id ~= 32 or not expiry or tonumber(expiry) < os.time()
       or tonumber(expiry) > os.time() + 60 or not state.registered
       or state.expires_at - os.time() < 40 or sub.restoring
       or (active_call and active_call.state ~= "done") then
        report.reason = "call prerequisites or request lifetime invalid"
        write_status("call-status", report)
        return
    end
    local control = assert(loadfile("/opt/dpt_call_control.lua"))()
    active_call = control.new{loop = loop, io = io_, sub = sub,
        destination = destination, originator = "sip:" .. msisdn .. "@" .. cfg.realm,
        mode = "call", authorized = true, hold_ms = 3000,
        on_event = function(event)
            report.state, report.last_event = "in-progress", event
            report.updated_at = os.time()
            write_status("call-status", report)
        end,
        on_done = function(call)
            active_request_id = nil
            state.call_active = false
            report.state, report.answered = "done", call.answered
            report.final_status, report.release_ok = call.final_status or 0, call.release_ok or false
            report.call_id, report.reason = call.call_id, call.reason
            report.updated_at = os.time()
            write_status("call-status", report)
            publish()
        end,
    }
    state.call_active = true
    active_request_id = id
    report.call_id = active_call.call_id
    write_status("call-status", report)
    active_call.start()
end
local function heartbeat()
    if stopping then return end
    if exists("stop") then return stop("stopped", false) end
    local ok, current = pcall(net.if_addr4, interface)
    if not ok or current ~= address then return stop("ims-tunnel-changed", true) end
    local cancel = io.open(state_dir .. "/call-stop", "r")
    if cancel then
        local request_id = cancel:read("*a"); cancel:close(); os.remove(state_dir .. "/call-stop")
        if request_id == active_request_id and active_call then active_call.stop() end
    end
    call_request()
    if exists("renew-now") then os.remove(state_dir .. "/renew-now"); renew() end
    if state.registered and os.time() >= state.expires_at then
        return stop("lease-expired", true)
    end
    publish()
    loop:after(2000, heartbeat)
end
local ok = pcall(function()
    sub.sock = net.UdpSocket(address, sub.port_uc)
    loop:add_fd(sub.sock:fd(), net.NET_RD, function() io_.drain(sub, sub.sock, message) end)
    sub.sock:tx_loop(loop, net.NET_RD)
    assert(io_.listen(sub, loop, message), "TCP listener required")
    state.state = "registering"; publish()
    flow.first_register(sub)
    loop:after(2000, heartbeat)
    loop:run()
end)
if not ok then
    failed = true
    pcall(function() flow.disarm(sub); flow.deregister() end)
    state.state, state.registered = "agent-error", false
    publish()
end
pcall(flow.release_sas)
pcall(flow.close_sockets)
os.exit(failed and 1 or 0)
