"""Sanitized readable SIP evidence from private packet captures."""
import json
import re
import struct
from pathlib import Path

HEADERS = {"via", "from", "to", "contact", "call-id", "cseq", "route", "record-route",
           "p-asserted-identity", "p-preferred-identity", "max-forwards", "supported",
           "allow", "content-type", "user-agent", "reason"}
METHODS = {"INVITE", "ACK", "BYE", "CANCEL", "PRACK"}
START = re.compile(
    rb"(?:INVITE|ACK|BYE|CANCEL|PRACK|OPTIONS|REGISTER|NOTIFY|SUBSCRIBE|UPDATE|MESSAGE)"
    rb" (?:sip:|sips:|tel:)[^\r\n\x00 ]+ SIP/2\.0\r?\n"
    rb"|SIP/2\.0 [1-6][0-9]{2} [^\r\n\x00]*\r?\n")


def redact(value):
    return re.sub(r"((?:sip|sips):[^@;\s<>:]+):[^@;\s<>]+@", r"\1:[redacted]@", value)


def messages(payload, point, timestamp=0):
    result = []
    for match in START.finditer(payload):
        remaining = payload[match.start():]
        separator = re.search(rb"\r?\n\r?\n", remaining)
        if separator is None or separator.start() > 16384:
            continue
        lines = remaining[:separator.start()].decode(errors="replace").splitlines()
        headers = {}
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            key = name.lower().strip()
            if key in HEADERS:
                headers[key] = (headers[key] + ", " if key in headers else "") + redact(value.strip())
        cseq = headers.get("cseq", "")
        method = cseq.split()[-1] if cseq.split() else ""
        if method not in METHODS or "call-id" not in headers:
            continue
        start = redact(lines[0])
        formatted = start + "\n" + "\n".join(
            key.title() + ": " + value for key, value in headers.items())
        result.append({"point": point, "timestamp": timestamp, "start_line": start,
                       "method": method, "call_id": headers["call-id"],
                       "cseq": cseq, "headers": headers, "message": formatted})
    return result


def pcap_messages(path, point):
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    formats = {"d4c3b2a1": ("<", 1e6), "a1b2c3d4": (">", 1e6),
               "4d3cb2a1": ("<", 1e9), "a1b23c4d": (">", 1e9)}
    if data[:4].hex() not in formats:
        raise ValueError("Unsupported private capture format")
    endian, resolution = formats[data[:4].hex()]
    offset, result = 24, []
    while offset + 16 <= len(data):
        sec, part, length, _ = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        if offset + length > len(data):
            break
        result.extend(messages(data[offset:offset + length], point, sec + part / resolution))
        offset += length
    return result


def extract(folder, call_id=None):
    folder = Path(folder).resolve()
    parent = (Path.home() / ".config/dan-powell-technologies/traces").resolve()
    if folder.parent != parent:
        raise ValueError("Only private lab trace folders are supported")
    events = []
    for point in ("ue", "pcscf", "scscf", "b2bua"):
        for path in sorted((folder / point).glob("trace.pcap*")):
            events.extend(pcap_messages(path, point))
    if call_id:
        events = [event for event in events if event["call_id"] == call_id
                  or event["point"] == "b2bua"]
    events.sort(key=lambda value: value["timestamp"])
    cleaned = []
    for event in events:
        if any(old["point"] == event["point"] and old["message"] == event["message"]
               and abs(old["timestamp"] - event["timestamp"]) < .005 for old in cleaned[-12:]):
            continue
        cleaned.append(event)
    result = {"scope": "Saved sanitized readable SIP; not TLS/ESP decryption or audio verification.",
              "events": cleaned[-300:]}
    (folder / "sip-trace.json").write_text(json.dumps(result, indent=2))
    return result


def render(trace, point=None):
    lines = []
    for event in trace["events"]:
        if point and event["point"] != point:
            continue
        lines.append("[" + event["point"] + "] " + event["start_line"]
                     + " · CSeq " + event["cseq"])
    return "\n".join(lines)
