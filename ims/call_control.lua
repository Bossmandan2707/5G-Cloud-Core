-- Single originating dialog using pro2call's SIP codecs and registered socket.
-- Preflight never expects an answer: the default-disarmed gateway must reject it.
local net = require("net")
local sip = require("sip")
local sdp = require("sdp")
local wire = require("ims.wire")
local M = {}

function M.new(o)
    local sub, loop, io_ = o.sub, o.loop, o.io
    local C = {state = "idle", events = {}, final_status = nil, answered = false}
    local mode = o.mode or "preflight"
    assert(mode == "preflight" or (mode == "call" and o.authorized == true),
           "external call requires explicit authorization")
    local hold_ms = o.hold_ms or 3000
    assert(type(hold_ms) == "number" and hold_ms >= 0 and hold_ms <= 5000,
           "answered-call hold must be at most five seconds")
    local id = ("dpt%.0f%06d"):format(net.now_ms(), math.random(0, 999999))
    C.call_id, C.branch = id .. "@" .. sub.ue_addr, "z9hG4bK" .. id
    local destination = assert(o.destination, "private destination required")
    assert(destination:match("^%+[1-9]%d+$") and #destination >= 9
           and #destination <= 16, "invalid E.164 destination")
    local realm = sub.impu:match("@([A-Za-z0-9.-]+)$")
    assert(realm, "registered IMS realm required")
    local uri = "sip:" .. destination .. "@" .. realm .. ";user=phone"
    local originator = o.originator or sub.impu
    local from = "<" .. originator .. ">;tag=" .. id
    local to, target, routes = "<" .. uri .. ">", uri, {}
    local cseq, timer, retry, invite_wire, finished = 1
    local pracks = {}

    local function event(what)
        C.events[#C.events + 1] = what
        if o.on_event then o.on_event(what) end
    end
    local function cancel_timer(t)
        if t then loop:cancel(t) end
    end
    local function arm(ms, fn)
        cancel_timer(timer)
        timer = loop:after(ms, function() timer = nil; fn() end)
    end
    local function finish(reason)
        if finished then return end
        finished = true
        cancel_timer(timer); cancel_timer(retry)
        C.state, C.reason = "done", reason
        event(reason)
        if o.on_done then o.on_done(C) end
    end
    local function build(method, label, sequence, branch, dialog, body, rack)
        local b = wire.builder:request(method, dialog and target or uri)
        if dialog then
            for _, r in ipairs(routes) do b:header(sip.H_ROUTE, r) end
        else
            io_.preload_route(b, sub)
        end
        b:header(sip.H_VIA, ("SIP/2.0/UDP %s;branch=%s"):format(wire.ue_at(sub), branch))
            :header_u32(sip.H_MAX_FORWARDS, 70)
            :header(sip.H_FROM, from):header(sip.H_TO, to)
            :header(sip.H_CALL_ID, C.call_id)
            :header(sip.H_CSEQ, ("%d %s"):format(sequence, label))
            :header(sip.H_CONTACT, sub.registered_contact or wire.contact(sub))
        if rack then b:header(sip.H_RACK, rack) end
        if method == sip.INVITE then
            b:header(sip.H_P_PREFERRED_IDENTITY, "<" .. originator .. ">")
                :header(sip.H_ALLOW, "INVITE, ACK, CANCEL, BYE, PRACK, OPTIONS")
                :header(sip.H_SUPPORTED, "100rel")
        end
        if body then b:header(sip.H_CONTENT_TYPE, "application/sdp") end
        return b:done(body or "")
    end
    local function send(bytes, what)
        local ok = io_.send(sub, "mo", bytes, what)
        event("sent " .. what)
        return ok
    end
    local function send_bye(reason)
        if C.state == "bye" or finished then return end
        C.state = "bye"
        cseq = cseq + 1
        local bytes = build(sip.BYE, "BYE", cseq, C.branch .. "b", true)
        send(bytes, "BYE")
        arm(4000, function() finish(reason .. "; BYE response timeout") end)
    end
    local function cancel_invite(reason)
        if finished or C.answered then return end
        C.state = "cancelling"
        send(build(sip.CANCEL, "CANCEL", 1, C.branch, false), "CANCEL")
        arm(5000, function() finish(reason .. "; no final INVITE response") end)
    end
    function C.start()
        assert(C.state == "idle", "one attempt per controller")
        assert(sub.registered and sub.protected, "authenticated IPsec registration required")
        assert(sub.sock and #(sub.svc_route or {}) > 0, "registered socket and Service-Route required")
        if originator ~= sub.impu then
            local known = false
            for _, identity in ipairs(sub.assoc or {}) do
                if wire.same_id(identity, originator) then known = true end
            end
            assert(known, "originator must be a network-associated public identity")
        end
        C.state = "inviting"
        local offer = sdp.offer{addr = sub.ue_addr, port = 40000,
                                pt = 0, codec = "PCMU", rate = 8000, ptime = 20}
        invite_wire = build(sip.INVITE, "INVITE", 1, C.branch, false, offer)
        if not send(invite_wire, "INVITE") then return finish("INVITE send failed") end
        local delay = 500
        local function retransmit()
            retry = nil
            if C.state ~= "inviting" then return end
            send(invite_wire, "INVITE retransmission")
            delay = math.min(delay * 2, 4000)
            retry = loop:after(delay, retransmit)
        end
        retry = loop:after(delay, retransmit)
        arm(15000, function() cancel_invite("ringing limit reached") end)
    end
    function C.handle(m)
        if m:call_id() ~= C.call_id then return false end
        if m.request then
            if m.method == sip.BYE then
                io_.send(sub, "mt", wire.response(sub, m, {
                    status = 200, reason = "OK", to_tag = id}), "200 OK (BYE)")
                finish("remote BYE")
            elseif m.method ~= sip.ACK then
                io_.send(sub, "mt", wire.response(sub, m, {
                    status = 405, reason = "Method Not Allowed", to_tag = id}), "405")
            end
            return true
        end
        local method = m:cseq().method
        local sequence = tonumber(m:header("CSeq"):match("^(%d+)"))
        if method == sip.INVITE and sequence ~= 1 then return false end
        if method == sip.BYE and sequence ~= cseq then return false end
        event(("received %d %s"):format(m.status, m:header("CSeq")))
        if method == sip.BYE then
            if m.status >= 200 then
                C.release_ok = m.status < 300
                finish(C.release_ok and "call released by BYE" or "BYE rejected")
            end
            return true
        end
        if method ~= sip.INVITE then return true end
        if m.status < 200 then
            cancel_timer(retry); retry = nil
            if m.status > 100 and m:header("Require"):lower():find("100rel", 1, true) then
                local rseq = tonumber(m:header("RSeq"))
                if not rseq then cancel_invite("invalid reliable provisional"); return true end
                if not pracks[rseq] then
                    to = m:header("To"); target = wire.contact_uri(m) or uri
                    routes = wire.route_set(m, true); cseq = cseq + 1
                    pracks[rseq] = build(sip.PRACK, "PRACK", cseq,
                        C.branch .. "p" .. cseq, true, nil, ("%d 1 INVITE"):format(rseq))
                end
                send(pracks[rseq], "PRACK")
            end
            return true
        end
        C.final_status = m.status
        to = m:header("To")
        cancel_timer(retry); retry = nil
        if m.status < 300 then
            target = wire.contact_uri(m) or uri
            routes = wire.route_set(m, true)
            send(build(sip.ACK, "ACK", 1, C.branch .. "a", true), "ACK")
            if finished then
                -- A late answer must still be cleared instead of leaving a call up.
                cseq = cseq + 1
                send(build(sip.BYE, "BYE", cseq, C.branch .. "late", true), "late BYE")
                return true
            end
            if C.answered then return true end
            C.answered = true
            if mode == "call" and C.state ~= "cancelling" then
                C.state = "answered"
                arm(hold_ms, function() send_bye("answered call hold complete") end)
            else
                send_bye("unexpected or late answer")
            end
        else
            send(build(sip.ACK, "ACK", 1, C.branch, false), "ACK (non-2xx)")
            finish("INVITE rejected locally or by IMS: " .. tostring(m.status))
        end
        return true
    end
    function C.stop()
        if not finished then
            if C.answered then send_bye("operator stop") else cancel_invite("operator stop") end
        end
    end
    return C
end

return M
