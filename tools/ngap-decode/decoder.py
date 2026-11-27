"""Decode N2 in-container; only allowlisted NGAP summaries leave this process."""
import argparse
import ipaddress
import json
import math
import re
import signal
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET


MAX_PACKET_XML = 2 * 1024 * 1024
PDU = "ngap.NGAP_PDU"
OUTCOMES = {0: "initiatingMessage", 1: "successfulOutcome", 2: "unsuccessfulOutcome"}
MESSAGES = {
    0: ("AMFConfigurationUpdate", "AMFConfigurationUpdateAcknowledge", "AMFConfigurationUpdateFailure"),
    1: ("AMFStatusIndication",),
    4: ("DownlinkNASTransport",),
    9: ("ErrorIndication",),
    10: ("HandoverCancel", "HandoverCancelAcknowledge"),
    11: ("HandoverNotify",),
    12: ("HandoverRequired", "HandoverCommand", "HandoverPreparationFailure"),
    13: ("HandoverRequest", "HandoverRequestAcknowledge", "HandoverFailure"),
    14: ("InitialContextSetupRequest", "InitialContextSetupResponse", "InitialContextSetupFailure"),
    15: ("InitialUEMessage",),
    16: ("LocationReportingControl",),
    17: ("LocationReportingFailureIndication",),
    18: ("LocationReport",),
    19: ("NASNonDeliveryIndication",),
    20: ("NGReset", "NGResetAcknowledge"),
    21: ("NGSetupRequest", "NGSetupResponse", "NGSetupFailure"),
    22: ("OverloadStart",),
    23: ("OverloadStop",),
    24: ("Paging",),
    25: ("PathSwitchRequest", "PathSwitchRequestAcknowledge", "PathSwitchRequestFailure"),
    26: ("PDUSessionResourceModifyRequest", "PDUSessionResourceModifyResponse"),
    27: ("PDUSessionResourceModifyIndication", "PDUSessionResourceModifyConfirm"),
    28: ("PDUSessionResourceReleaseCommand", "PDUSessionResourceReleaseResponse"),
    29: ("PDUSessionResourceSetupRequest", "PDUSessionResourceSetupResponse"),
    30: ("PDUSessionResourceNotify",),
    35: ("RANConfigurationUpdate", "RANConfigurationUpdateAcknowledge", "RANConfigurationUpdateFailure"),
    36: ("RerouteNASRequest",),
    37: ("RRCInactiveTransitionReport",),
    40: ("UEContextModificationRequest", "UEContextModificationResponse", "UEContextModificationFailure"),
    41: ("UEContextReleaseCommand", "UEContextReleaseComplete"),
    42: ("UEContextReleaseRequest",),
    43: ("UERadioCapabilityCheckRequest", "UERadioCapabilityCheckResponse"),
    44: ("UERadioCapabilityInfoIndication",),
    45: ("UETNLABindingReleaseRequest",),
    46: ("UplinkNASTransport",),
    52: ("SecondaryRATDataUsageReport",),
}
CAUSES = ("radioNetwork", "transport", "nas", "protocol", "misc")
OUTPUT_LOCK = threading.Lock()


def fields(node):
    """Do not accidentally assign a nested NGAP PDU's IEs to its parent."""
    yield node
    for child in node:
        if child.get("name") != PDU:
            yield from fields(child)


def scalar(nodes, name, maximum=None):
    values = {n.get("show") for n in nodes if n.get("name") == name}
    values.discard(None)
    if not values:
        return None
    if len(values) != 1:
        raise ValueError("Ambiguous scalar")
    value = values.pop()
    if maximum is not None:
        if not re.fullmatch(r"(?:[0-9]{1,16}|0x[0-9a-fA-F]{1,16})", value):
            raise ValueError("Invalid numeric field")
        value = int(value, 16 if value.startswith("0x") else 10)
        if value > maximum:
            raise ValueError("Numeric field out of range")
    return value


def decode_packet(packet):
    """Convert one PDML packet to one event per PDU; never export showname or bodies."""
    if packet.tag != "packet":
        raise ValueError("Not a packet")
    if any(n.get("name") in ("_ws.malformed", "_ws.malformed.expert")
           for n in packet.iter()):
        raise ValueError("Malformed packet")
    frame = [n for p in packet.findall("proto") if p.get("name") == "frame" for n in p.iter()]
    ip = [n for p in packet.findall("proto") if p.get("name") == "ip" for n in p.iter()]
    sctp = [n for p in packet.findall("proto") if p.get("name") == "sctp" for n in p.iter()]
    timestamp = float(scalar(frame, "frame.time_epoch"))
    if not math.isfinite(timestamp) or not 0 <= timestamp <= 253402300799:
        raise ValueError("Invalid timestamp")
    metadata = {
        "timestamp": timestamp,
        "source": str(ipaddress.IPv4Address(scalar(ip, "ip.src"))),
        "destination": str(ipaddress.IPv4Address(scalar(ip, "ip.dst"))),
        "source_port": scalar(sctp, "sctp.srcport", 65535),
        "destination_port": scalar(sctp, "sctp.dstport", 65535),
        "frame_bytes": scalar(frame, "frame.len", 65549),
    }
    if any(metadata[k] is None for k in ("source_port", "destination_port", "frame_bytes")):
        raise ValueError("Missing transport metadata")
    streams = {n.get("show") for n in sctp if n.get("name") == "sctp.data_sid"}
    # Bundled DATA chunks can use distinct streams; do not guess their association.
    stream = scalar(sctp, "sctp.data_sid", 65535) if len(streams) <= 1 else None
    events = []
    for pdu in (n for n in packet.iter("field") if n.get("name") == PDU):
        nodes = list(fields(pdu))
        outcome = scalar([pdu], PDU, 2)
        if outcome is None:
            raise ValueError("Missing NGAP outcome")
        branch = next((n for n in pdu if n.get("name") ==
                       "ngap." + OUTCOMES[outcome] + "_element"), pdu)
        procedure = scalar(list(branch), "ngap.procedureCode", 255)
        criticality = scalar(list(branch), "ngap.criticality", 2)
        if procedure is None or criticality is None:
            raise ValueError("Incomplete NGAP PDU")
        known = MESSAGES.get(procedure, ())
        name = known[outcome] if outcome < len(known) else None
        if name and not any(n.get("name") == "ngap." + name + "_element" for n in nodes):
            raise ValueError("Message type does not match procedure/outcome")
        causes = [{"category": category, "value": scalar(nodes, "ngap." + category, 65535)}
                  for category in CAUSES]
        events.append({
            **metadata, "pdu_index": len(events), "message": name or "Unknown NGAP procedure",
            "procedure_code": procedure, "outcome": OUTCOMES[outcome],
            "criticality": criticality, "stream": stream,
            "ran_context_id": scalar(nodes, "ngap.RAN_UE_NGAP_ID", 2**32 - 1),
            "amf_context_id": scalar(nodes, "ngap.AMF_UE_NGAP_ID", 2**40 - 1),
            "causes": [cause for cause in causes if cause["value"] is not None],
        })
        if len(events) > 64:
            raise ValueError("Too many bundled PDUs")
    return events


def emit(record):
    with OUTPUT_LOCK:
        print(json.dumps(record, allow_nan=False, separators=(",", ":")), flush=True)


def read_pdml(stream):
    lines, size, dropping = [], 0, False
    for line in iter(lambda: stream.readline(MAX_PACKET_XML + 1), b""):
        if b"<packet>" in line:
            lines, size, dropping = [], 0, False
        if lines or b"<packet>" in line or dropping:
            size += len(line)
            if size > MAX_PACKET_XML:
                lines, dropping = [], True
            elif not dropping:
                lines.append(line)
            if b"</packet>" in line:
                try:
                    if dropping:
                        raise ValueError("Oversized packet")
                    events = decode_packet(ET.fromstring(b"".join(lines)))
                    for event in events:
                        emit({"type": "event", "event": event})
                except (ValueError, TypeError, ET.ParseError):
                    emit({"type": "warning", "reason": "malformed_or_ambiguous_packet"})
                lines, size, dropping = [], 0, False
    if lines or dropping:
        emit({"type": "warning", "reason": "truncated_decoder_output"})


def check():
    result = subprocess.run(["tshark", "-G", "fields"], capture_output=True, check=True, timeout=30)
    for field in (PDU, "ngap.procedureCode", "ngap.criticality", "ngap.NGSetupRequest_element",
                  "ngap.ErrorIndication_element", "ngap.RAN_UE_NGAP_ID", "ngap.AMF_UE_NGAP_ID"):
        if ("\t" + field + "\t").encode() not in result.stdout:
            raise ValueError("Required NGAP decoder field unavailable")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--stdin", action="store_true", help="Decode synthetic/offline PCAP from stdin")
    parser.add_argument("--port", type=int, default=38412)
    args = parser.parse_args()
    if args.check:
        check()
        print("NGAP decoder fields verified")
        return 0
    if not 0 < args.port <= 65535:
        parser.error("Invalid SCTP port")
    capture = decoder = None

    def terminate(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    try:
        source = sys.stdin.buffer
        if not args.stdin:
            capture = subprocess.Popen(
                ["tcpdump", "-p", "-i", "lo", "-nn", "-U", "-s", "0", "-w", "-",
                 "sctp", "port", str(args.port)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            source = capture.stdout
        decoder = subprocess.Popen(
            ["tshark", "-n", "-l", "-r", "-", "-d", f"sctp.port=={args.port},ngap",
             "-o", "sctp.reassembly:TRUE", "-Y", "ngap || _ws.malformed", "-T", "pdml"],
            stdin=source, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if capture:
            capture.stdout.close()

            def readiness():
                for line in iter(lambda: capture.stderr.readline(4096), b""):
                    if b"listening on lo" in line:
                        emit({"type": "ready"})
            threading.Thread(target=readiness, daemon=True).start()
        read_pdml(decoder.stdout)
        code = decoder.wait(timeout=10)
        if code or (capture and capture.poll() is not None):
            emit({"type": "error", "reason": "decoder_or_capture_exited"})
            return 2
        return 0
    except KeyboardInterrupt:
        return 0
    except (OSError, ValueError, subprocess.SubprocessError):
        emit({"type": "error", "reason": "decoder_unavailable"})
        return 2
    finally:
        for process in (capture, decoder):
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                for stream in (process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
