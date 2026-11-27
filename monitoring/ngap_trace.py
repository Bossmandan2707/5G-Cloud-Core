"""N2 SCTP transport metadata, not decoded NGAP procedures or subscriber data."""
import ipaddress
import math
import re
import subprocess
import time

import yaml

from gtp_trace import GtpCapture, TraceBuffer
from interfaces import ROOT


PACKET = re.compile(
    r"^(\d+\.\d+)\s+.*?\bIPv4(?: \(0x0800\))?, length (\d+): "
    r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > "
    r"(\d+\.\d+\.\d+\.\d+)\.(\d+): sctp\b"
)
DIRECTIONS = ("UL", "DL", "OTHER")


def load_layout(path=ROOT / "open5gs-pod.yaml"):
    documents = yaml.safe_load_all(path.read_text())
    config = next(d["data"] for d in documents if isinstance(d, dict)
                  and d.get("kind") == "ConfigMap"
                  and d.get("metadata", {}).get("name") == "open5gs-config")
    amf = yaml.safe_load(config["amf.yaml"])["amf"]["ngap"]["server"][0]
    gnb = yaml.safe_load(config["gnb.yaml"])
    return [{"component": "AMF", "service": "ngap", "address": amf["address"],
             "port": amf.get("port", 38412)},
            {"component": "gNB", "service": "ngap", "address": gnb["ngapIp"]}]


def parse_packet(line, amf="127.0.0.5", gnb="127.0.0.1", port=38412):
    match = PACKET.match(line)
    if not match:
        return None
    timestamp, length, src, sport, dst, dport = match.groups()
    try:
        ipaddress.IPv4Address(src)
        ipaddress.IPv4Address(dst)
        sport, dport, length = int(sport), int(dport), int(length)
        timestamp = float(timestamp)
        if not math.isfinite(timestamp) or not 0 <= timestamp <= 253402300799:
            return None
        if not (0 < sport <= 65535 and 0 < dport <= 65535 and 34 <= length <= 65549):
            return None
    except ValueError:
        return None
    if port not in (sport, dport):
        return None
    direction = "OTHER"
    if src == gnb and dst == amf and dport == port:
        direction = "UL"
    elif src == amf and dst == gnb and sport == port:
        direction = "DL"
    return {"timestamp": timestamp, "source": src, "source_port": sport,
            "destination": dst, "destination_port": dport,
            "bytes": length, "direction": direction}


def association_summary(interfaces, now=None):
    """Never promote stale or unavailable kernel observations to established."""
    now = time.time() if now is None else now
    core = interfaces.get("namespaces", {}).get("core", {})
    updated = core.get("updated")
    stale = (interfaces.get("stale", True) or updated is None
             or now - updated > 45)
    link = next((r for r in interfaces.get("links", []) if r.get("name") == "N2"), {})
    status = "stale" if stale else "unknown" if core.get("error") else link.get("status", "unknown")
    return {"status": status, "stale": bool(stale), "updated": updated,
            "left": link.get("left"), "right": link.get("right"),
            "note": "Kernel SCTP observation, not proof of NGAP registration or a successful procedure."}


class NgapBuffer(TraceBuffer):
    def __init__(self, limit=500):
        super().__init__(limit)
        self.message = "Starting N2 SCTP capture…"
        self.endpoints = None

    def configure(self, amf, gnb, port):
        with self.lock:
            self.endpoints = {"amf": amf, "gnb": gnb, "port": port}

    def snapshot(self, now=None):
        second = int(time.monotonic() if now is None else now)
        with self.lock:
            self._prune(second)
            rates = {}
            for direction in DIRECTIONS:
                count = sum(self.bins.get(s, {}).get(direction + "_packets", 0)
                            for s in range(second - 4, second + 1))
                size = sum(self.bins.get(s, {}).get(direction + "_bytes", 0)
                           for s in range(second - 4, second + 1))
                rates[direction] = {"pps": count / 5, "mbps": size * 8 / 5 / 1e6}
            history = [
                {"seconds_ago": second - s,
                 **{d: self.bins.get(s, {}).get(d + "_packets", 0) for d in DIRECTIONS}}
                for s in range(second - 59, second + 1)
            ]
            return {"status": self.status, "message": self.message,
                    "last_seen": self.last_seen, "updated": time.time(),
                    "packets": [dict(p) for p in self.packets], "totals": dict(self.totals),
                    "rates": rates, "history": history, "buffer_limit": self.packets.maxlen,
                    "endpoints": dict(self.endpoints) if self.endpoints else None,
                    "capture": "Core pod lo · N2 SCTP · frame metadata only",
                    "scope": "All SCTP transport packets on the configured NGAP port, including "
                             "heartbeats and acknowledgements; not decoded NGAP messages. "
                             "Frame bytes include the loopback Ethernet header. No payloads retained."}


class NgapCapture(GtpCapture):
    """Reuse the existing thread and owned-helper cleanup, with a fixed SCTP filter."""
    def __init__(self, podman, buffer):
        super().__init__(podman, buffer)
        self.helper = self.helper.replace("dpt-gtp-", "dpt-ngap-", 1)

    def run(self):
        if self.stop.is_set():
            return
        if not self.podman:
            self.buffer.set_status("error", "Podman executable not found.")
            return
        try:
            layout = load_layout()
            endpoint = next(e for e in layout if e["component"] == "AMF" and e["service"] == "ngap")
            amf = str(ipaddress.IPv4Address(endpoint["address"]))
            gnb = str(ipaddress.IPv4Address(next(
                e["address"] for e in layout if e["component"] == "gNB" and e["service"] == "ngap")))
            if not (ipaddress.IPv4Address(amf).is_loopback and ipaddress.IPv4Address(gnb).is_loopback):
                raise ValueError("This capture requires core-pod loopback N2 endpoints")
            port = int(endpoint["port"])
            if not 0 < port <= 65535:
                raise ValueError("Invalid NGAP port")
            self.buffer.configure(amf, gnb, port)
            subprocess.run(
                [self.podman, "run", "-d", "--name", self.helper,
                 "--label", "io.dpt.ngap-capture=true", "--pod", "open5gs",
                 "--cap-drop", "ALL", "--cap-add", "NET_RAW",
                 "--read-only", "--pids-limit", "64", "--memory", "32m",
                 "--security-opt", "label=disable", "gtpu-mon:0.1", "sleep", "2147483647"],
                capture_output=True, text=True, timeout=30, check=True,
            )
            while not self.stop.is_set():
                self.buffer.set_status("starting", "Opening N2 SCTP capture…")
                self.process = subprocess.Popen(
                    [self.podman, "exec", self.helper, "timeout", "45",
                     "tcpdump", "-p", "-i", "lo", "-nn", "-l", "-tt", "-q", "-e",
                     "-s", "96", "sctp", "port", str(port)],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
                )
                for line in self.process.stdout:
                    if self.stop.is_set():
                        break
                    packet = parse_packet(line, amf, gnb, port)
                    if packet:
                        self.buffer.add(packet)
                    elif "listening on lo" in line:
                        self.buffer.set_status("live", "N2 capture live. Idle is normal; heartbeats are not NGAP procedures.")
                    elif "tcpdump:" in line and "verbose output" not in line:
                        self.buffer.set_status("error", "N2 capture reported an error; check the core pod and capture image.")
                code = self.process.wait(timeout=8)
                self.process.stdout.close()
                if self.stop.is_set():
                    break
                if code not in (0, 124):
                    self.buffer.set_status("error", "N2 capture exited unexpectedly; restart the monitor after checking the core pod.")
                    break
                self.stop.wait(0.25)
        except (OSError, ValueError, KeyError, IndexError, TypeError, StopIteration,
                yaml.YAMLError, subprocess.SubprocessError):
            self.buffer.set_status("error", "N2 capture unavailable. Check the core manifest, Podman, open5gs pod and gtpu-mon:0.1 image.")
        finally:
            self._remove_helper()
            self._reap_process()
