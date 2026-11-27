"""Host-side bounded storage and lifecycle for sanitized in-container NGAP decode."""
from collections import deque
import copy
import ipaddress
import json
import math
import re
import subprocess
import threading
import time

import yaml

from gtp_trace import GtpCapture
from ngap_trace import load_layout


IMAGE = "localhost/ngap-decode:0.1"
OUTCOMES = ("initiatingMessage", "successfulOutcome", "unsuccessfulOutcome")
EVENT_KEYS = {"timestamp", "source", "destination", "source_port", "destination_port",
              "frame_bytes", "pdu_index", "message", "procedure_code", "outcome",
              "criticality", "stream", "ran_context_id", "amf_context_id", "causes"}


def validate_event(event, endpoints):
    if not isinstance(event, dict) or set(event) != EVENT_KEYS:
        raise ValueError("Unexpected decoded event fields")
    event = copy.deepcopy(event)
    for name in ("source", "destination"):
        event[name] = str(ipaddress.IPv4Address(event[name]))
        if not ipaddress.IPv4Address(event[name]).is_loopback:
            raise ValueError("Not a core-pod loopback address")
    timestamp = event["timestamp"]
    if (type(timestamp) not in (int, float) or not math.isfinite(timestamp)
            or not 0 <= timestamp <= 253402300799):
        raise ValueError("Invalid timestamp")
    for key, minimum, maximum in (
        ("source_port", 1, 65535), ("destination_port", 1, 65535), ("frame_bytes", 34, 65549),
        ("pdu_index", 0, 63), ("procedure_code", 0, 255), ("criticality", 0, 2),
        ("stream", 0, 65535), ("ran_context_id", 0, 2**32 - 1),
        ("amf_context_id", 0, 2**40 - 1),
    ):
        value = event[key]
        if value is None and key in ("criticality", "stream", "ran_context_id", "amf_context_id"):
            continue
        if type(value) is not int or not minimum <= value <= maximum:
            raise ValueError("Invalid numeric metadata")
    if event["outcome"] not in OUTCOMES:
        raise ValueError("Invalid NGAP outcome")
    name = event["message"]
    if not isinstance(name, str) or not (name == "Unknown NGAP procedure" or
                                        re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,79}", name)):
        raise ValueError("Invalid NGAP message name")
    causes = event["causes"]
    if not isinstance(causes, list) or len(causes) > 5:
        raise ValueError("Invalid cause list")
    for cause in causes:
        if (not isinstance(cause, dict) or set(cause) != {"category", "value"}
                or cause["category"] not in ("radioNetwork", "transport", "nas", "protocol", "misc")
                or type(cause["value"]) is not int or not 0 <= cause["value"] <= 65535):
            raise ValueError("Invalid numeric cause")
    amf, gnb, port = endpoints["amf"], endpoints["gnb"], endpoints["port"]
    if port not in (event["source_port"], event["destination_port"]):
        raise ValueError("Not the configured NGAP port")
    event["direction"] = "OTHER"
    if event["source"] == gnb and event["destination"] == amf and event["destination_port"] == port:
        event["direction"] = "UL"
    elif event["source"] == amf and event["destination"] == gnb and event["source_port"] == port:
        event["direction"] = "DL"
    return event


class DecoderBuffer:
    def __init__(self, limit=200):
        self.lock = threading.Lock()
        self.events = deque(maxlen=limit)
        self.sequence = self.rejected = 0
        self.status = "starting"
        self.message = "Starting NGAP message decoder…"
        self.endpoints = None
        self.last_seen = None

    def set_status(self, status, message):
        with self.lock:
            self.status, self.message = status, message

    def configure(self, amf, gnb, port):
        with self.lock:
            self.endpoints = {"amf": amf, "gnb": gnb, "port": port}

    def reject(self):
        with self.lock:
            self.rejected += 1

    def accept(self, record):
        if not isinstance(record, dict):
            raise ValueError("Not a decoder record")
        kind = record.get("type")
        if kind == "ready" and set(record) == {"type"}:
            self.set_status("live", "Decoder live. Waiting for new NGAP procedures; SCTP heartbeats are excluded.")
        elif kind == "event" and set(record) == {"type", "event"}:
            with self.lock:
                if self.endpoints is None:
                    raise ValueError("Decoder endpoints unavailable")
                event = validate_event(record["event"], self.endpoints)
                self.sequence += 1
                self.events.append({**event, "id": self.sequence})
                self.last_seen = time.time()
        elif kind == "warning" and record.get("reason") in (
                "malformed_or_ambiguous_packet", "truncated_decoder_output"):
            self.reject()
        elif kind == "error":
            self.set_status("error", "NGAP decoder failed; check the helper image and core-pod capture access.")
        else:
            raise ValueError("Unexpected decoder record")

    def snapshot(self):
        with self.lock:
            return {"status": self.status, "message": self.message,
                    "events": copy.deepcopy(list(self.events)), "total_events": self.sequence,
                    "rejected_records": self.rejected, "buffer_limit": self.events.maxlen,
                    "last_seen": self.last_seen,
                    "scope": "Decoded NGAP PDU headers and selected numeric context/cause fields only. "
                             "No NAS contents, security keys, IMSI/SUCI/GUTI, generic Info text or raw packets. "
                             "Context IDs are transient NGAP handles, not subscriber identities. "
                             "Stream is unknown if bundled chunks cannot be attributed unambiguously. "
                             "Capture restarts every 120s can lose fragments; this is not a lossless recorder."}


class NgapDecoder(GtpCapture):
    def __init__(self, podman, buffer):
        super().__init__(podman, buffer)
        self.helper = self.helper.replace("dpt-gtp-", "dpt-ngap-decode-", 1)

    def run(self):
        if self.stop.is_set():
            return
        if not self.podman:
            self.buffer.set_status("error", "Podman executable not found.")
            return
        try:
            available = subprocess.run([self.podman, "image", "exists", IMAGE],
                                       capture_output=True, timeout=10)
            if available.returncode:
                self.buffer.set_status("error", "Decoder image missing. Build: podman build -t ngap-decode:0.1 tools/ngap-decode")
                return
            layout = load_layout()
            amf = next(e for e in layout if e["component"] == "AMF")
            gnb = next(e for e in layout if e["component"] == "gNB")
            address, peer = str(ipaddress.IPv4Address(amf["address"])), str(ipaddress.IPv4Address(gnb["address"]))
            port = int(amf["port"])
            if not (ipaddress.IPv4Address(address).is_loopback
                    and ipaddress.IPv4Address(peer).is_loopback and 0 < port <= 65535):
                raise ValueError("Unexpected N2 endpoints")
            self.buffer.configure(address, peer, port)
            subprocess.run(
                [self.podman, "run", "-d", "--name", self.helper,
                 "--label", "io.dpt.ngap-decoder=true", "--pod", "open5gs",
                 "--cap-drop", "ALL", "--cap-add", "NET_RAW", "--read-only",
                 "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
                 "--pids-limit", "64", "--memory", "256m", "--security-opt", "label=disable",
                 IMAGE, "sleep", "2147483647"],
                capture_output=True, text=True, timeout=30, check=True)
            while not self.stop.is_set():
                self.buffer.set_status("starting", "Opening decoded NGAP capture…")
                self.process = subprocess.Popen(
                    [self.podman, "exec", self.helper, "timeout", "-s", "TERM", "120",
                     "python3", "/decoder.py", "--port", str(port)],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
                for line in iter(lambda: self.process.stdout.readline(16385), ""):
                    if self.stop.is_set():
                        break
                    if len(line) > 16384:
                        while line and not line.endswith("\n"):
                            line = self.process.stdout.readline(16385)
                        self.buffer.reject()
                        continue
                    try:
                        self.buffer.accept(json.loads(line))
                    except (ValueError, TypeError, KeyError):
                        self.buffer.reject()
                code = self.process.wait(timeout=10)
                self.process.stdout.close()
                if self.stop.is_set():
                    break
                if code not in (0, 124):
                    self.buffer.set_status("error", "NGAP decoder exited unexpectedly; transport monitoring remains separate.")
                    break
                self.stop.wait(0.25)
        except (OSError, ValueError, KeyError, IndexError, TypeError, StopIteration,
                yaml.YAMLError, subprocess.SubprocessError):
            self.buffer.set_status("error", "NGAP decode unavailable; check the helper image, configuration and core pod.")
        finally:
            self._remove_helper()
            self._reap_process()
