-- Run inside the pinned pro2call image; fake I/O means no network messages.
package.path = "/opt/?.lua;" .. package.path
local sip = require("sip")
local control = require("dpt_call_control")
local total = 0
local function fixture(options)
    local sent, timers, completed = {}, {}, {}
    local sub = {ue_addr = "192.0.2.2", pcscf = "192.0.2.1", port_uc = 5060,
        impu = "sip:test@ims.example", registered = true, protected = true,
        svc_route = {"<sip:orig@scscf.ims.example;lr>"}, sock = {}}
    local loop = {}
    function loop:after(ms, fn)
        local t = {ms = ms, fn = fn}; timers[#timers + 1] = t; return t
    end
    function loop:cancel(t) t.cancelled = true end
    local io_ = {}
    function io_.send(_, _, bytes)
        sent[#sent + 1] = bytes
        return true
    end
    function io_.preload_route(b)
        b:header(sip.H_ROUTE, "<sip:orig@192.0.2.1:6100;lr>")
        for _, r in ipairs(sub.svc_route) do b:header(sip.H_ROUTE, r) end
        return b
    end
    local parameters = {loop = loop, io = io_, sub = sub,
        destination = "+12025550101",
        on_done = function(value) completed[#completed + 1] = value end}
    for key, value in pairs(options or {}) do parameters[key] = value end
    local c = control.new(parameters)
    return c, sub, sent, timers, completed
end
local function response(request, status, headers)
    local m = sip.parse(request)
    local b = sip.Builder():response(status, status == 200 and "OK" or "Test")
    b:header(sip.H_VIA, m:header("Via"))
        :header(sip.H_FROM, m:header("From"))
        :header(sip.H_TO, m:header("To") .. ";tag=remote")
        :header(sip.H_CALL_ID, m:header("Call-ID"))
        :header(sip.H_CSEQ, m:header("CSeq"))
        :header(sip.H_CONTACT, "<sip:peer@192.0.2.3:5060>")
        :header(sip.H_RECORD_ROUTE, "<sip:scscf.ims.example;lr>")
        :header(sip.H_RECORD_ROUTE, "<sip:pcscf.ims.example;lr>")
    for _, h in ipairs(headers or {}) do b:header(h[1], h[2]) end
    return sip.parse(b:done())
end
local function test(name, fn)
    fn(); total = total + 1; print("PASS " .. name)
end
test("fail closed without protected registration", function()
    for _, field in ipairs({"registered", "protected", "sock"}) do
        local c, sub, sent = fixture()
        sub[field] = false
        assert(not pcall(c.start)); assert(#sent == 0)
    end
    local c, sub, sent = fixture()
    sub.svc_route = {}; assert(not pcall(c.start)); assert(#sent == 0)
end)
test("INVITE preserves registered identity and originating routes", function()
    local c, sub, sent = fixture(); c.start()
    local m = sip.parse(sent[1])
    assert(m.method == sip.INVITE)
    assert(sent[1]:find("INVITE sip:+12025550101@ims.example;user=phone SIP/2.0", 1, true))
    assert(m:header("From"):find(sub.impu, 1, true))
    assert(m:header("P-Preferred-Identity") == "<" .. sub.impu .. ">")
    assert(m:header("Route"):find("orig@", 1, true))
    assert(m.body:find("192.0.2.2", 1, true))
    assert(not pcall(c.start))
end)
test("registrar-confirmed contact parameters are retained", function()
    local c, sub, sent = fixture()
    sub.registered_contact = "<sip:192.0.2.2:5060;transport=udp;alias=192.0.2.2~5060~1>"
    c.start()
    assert(sip.parse(sent[1]):header("Contact") == sub.registered_contact)
end)
test("non-2xx final is ACKed on the original transaction", function()
    local c, _, sent, _, completed = fixture(); c.start()
    c.handle(response(sent[1], 403))
    local invite, ack = sip.parse(sent[1]), sip.parse(sent[2])
    assert(ack.method == sip.ACK)
    assert(ack:header("Via") == invite:header("Via"))
    assert(ack:header("CSeq") == "1 ACK")
    assert(c.state == "done" and #completed == 1)
    c.handle(response(sent[1], 403)); assert(#completed == 1)
end)
test("reliable provisional gets one PRACK transaction per RSeq", function()
    local c, _, sent = fixture(); c.start()
    local m = response(sent[1], 183, {
        {sip.H_REQUIRE, "100rel"}, {sip.H_RSEQ, "7"}})
    c.handle(m); local first = sent[2]
    assert(sip.parse(first).method == sip.PRACK)
    assert(sip.parse(first):header("RAck") == "7 1 INVITE")
    c.handle(m); assert(sent[3] == first)
end)
test("ringing timeout sends CANCEL then ACKs 487", function()
    local c, _, sent, timers = fixture(); c.start()
    for _, t in ipairs(timers) do if t.ms == 15000 then t.fn(); break end end
    local cancel = sip.parse(sent[2]); assert(cancel.method == sip.CANCEL)
    assert(cancel:header("Via") == sip.parse(sent[1]):header("Via"))
    c.handle(response(sent[1], 487))
    assert(sip.parse(sent[3]).method == sip.ACK and c.state == "done")
end)
test("unexpected answer is immediately ACKed and cleared", function()
    local c, _, sent = fixture(); c.start()
    c.handle(response(sent[1], 200))
    assert(sip.parse(sent[2]).method == sip.ACK)
    assert(sip.parse(sent[3]).method == sip.BYE)
    local bye = sent[3]
    c.handle(response(sent[1], 200))
    assert(sip.parse(sent[4]).method == sip.ACK and #sent == 4)
    c.handle(response(bye, 200))
    assert(c.answered and c.state == "done")
end)
test("unrelated Call-ID is ignored", function()
    local c, _, sent = fixture(); c.start()
    local other = sent[1]:gsub(c.call_id, "unrelated", 1)
    assert(not c.handle(response(other, 403)))
    assert(c.state == "inviting")
end)
test("outbound mode requires explicit authorization", function()
    assert(not pcall(function() fixture{mode = "call"} end))
    assert(not pcall(function() fixture{mode = "call", authorized = true, hold_ms = 6000} end))
end)
test("authorized answer holds briefly then sends BYE", function()
    local c, _, sent, timers = fixture{mode = "call", authorized = true, hold_ms = 3000}
    c.start(); c.handle(response(sent[1], 200))
    assert(#sent == 2 and sip.parse(sent[2]).method == sip.ACK)
    for _, t in ipairs(timers) do
        if t.ms == 3000 and not t.cancelled then t.fn(); break end
    end
    assert(sip.parse(sent[3]).method == sip.BYE)
    c.handle(response(sent[3], 200))
    assert(c.release_ok and c.state == "done")
end)
test("originating public identity must be network-associated", function()
    local identity = "sip:public@ims.example"
    local c, sub, sent = fixture{originator = identity}
    assert(not pcall(c.start)); assert(#sent == 0)
    c, sub, sent = fixture{originator = identity}
    sub.assoc = {identity}
    c.start()
    assert(sip.parse(sent[1]):header("From"):find(identity, 1, true))
    assert(sip.parse(sent[1]):header("P-Preferred-Identity") == "<" .. identity .. ">")
end)
print(("Native signaling tests: %d passed; zero network I/O"):format(total))
