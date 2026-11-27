-- Registration plus one default-disarmed IMS preflight; no PSTN arming here.
package.path = "/opt/?.lua;" .. package.path
local net = require("net")
local sip = require("sip")
local cfg = require("ims.cfg")
local ue = require("ims.ue")
local sipio = require("ims.sipio")
local regflow = require("ims.regflow")
local wire = require("ims.wire")
local control = require("dpt_call_control")

assert(cfg.nsubs == 1, "one subscriber per preflight")
assert(cfg.require_ipsec and not cfg.verbose and not cfg.dump,
       "IPsec required and secret/digest logging must be disabled")
local destination = assert(os.getenv("DPT_CALL_DESTINATION"), "private destination required")
assert(destination:match("^%+[1-9]%d+$") and #destination >= 9
       and #destination <= 16, "invalid private E.164 destination")
local address = assert(os.getenv("IMS_UE_IP"), "actual IMS UE address required")
local pcscf = assert(os.getenv("PCSCF_IP"), "P-CSCF address required")
local loop = net.Loop()
local sub = ue.new(1)
sub.ue_addr, sub.pcscf = address, pcscf
local stats = {tx = 0, rx = 0, regs = 0, protected = 0, sa_fail = 0,
               latency = {}, start = net.now_ms()}
local io_ = sipio.new(stats)
local flow, call, ended, result, stop_timer

local function cleanup(reason)
    if ended then return end
    ended = true
    if stop_timer then loop:cancel(stop_timer) end
    result = reason
    print("DPT_RESULT " .. reason)
    flow.disarm(sub)
    flow.deregister()
    loop:after(1200, function() loop:stop() end)
end

flow = regflow.new{
    loop = loop, io = io_, stats = stats, subs = {sub},
    on_registered = function(_, m)
        local contact = wire.contact_uri(m)
        local own = "sip:" .. wire.ue_at(sub)
        assert(contact and contact:sub(1, #own) == own
               and (contact:sub(#own + 1, #own + 1) == ";" or #contact == #own),
               "registration response must confirm this UE contact")
        sub.registered_contact = "<" .. contact .. ">"
        print("DPT_REGISTERED protected=" .. tostring(sub.protected)
              .. " service_routes=" .. tostring(#(sub.svc_route or {})))
    end,
    on_terminal = function()
        if sub.done or ended then return end
        sub.done = true
        if not sub.registered then
            local error = sub.err or ""
            print("DPT_REGISTRATION_FAILURE stage=" .. tostring(sub.fail_stage)
                  .. " sip_status=" .. tostring(error:match("registration rejected: (%d+)"))
                  .. " timeout=" .. tostring(error:find("timed out", 1, true) ~= nil)
                  .. " aka_error=" .. tostring(error:find("AUTN", 1, true) ~= nil))
            return cleanup("registration failed")
        end
        flow.disarm(sub)
        -- Retain the registration long enough to inspect its actual contact.
        loop:after(2000, function()
            call = control.new{loop = loop, io = io_, sub = sub, destination = destination,
                on_event = function(event) print("DPT_SIP " .. event) end,
                on_done = function(c)
                    cleanup("preflight_status=" .. tostring(c.final_status)
                            .. " unexpected_answer=" .. tostring(c.answered))
                end}
            call.start()
        end)
    end,
}

local function on_message(_, m)
    if call and call.handle(m) then return end
    if not m.request then flow.handle(sub, m) end
end
sub.sock = net.UdpSocket(address, sub.port_uc)
loop:add_fd(sub.sock:fd(), net.NET_RD, function() io_.drain(sub, sub.sock, on_message) end)
sub.sock:tx_loop(loop, net.NET_RD)
assert(io_.listen(sub, loop, on_message), "protected TCP listener required")
stop_timer = loop:after(35000, function()
    if call then call.stop() end
    cleanup("overall preflight deadline")
end)
flow.first_register(sub)
local ok, error = pcall(function() loop:run() end)
if not ended then
    pcall(function() flow.disarm(sub); flow.deregister() end)
end
flow.release_sas()
flow.close_sockets()
if not ok then
    print("DPT_ERROR event loop failed; contact_confirmation="
          .. tostring(tostring(error):find("registration response must confirm", 1, true) ~= nil))
end
local rejected = call and call.final_status and call.final_status >= 300
os.exit(ok and rejected and not call.answered and 0 or 1)
