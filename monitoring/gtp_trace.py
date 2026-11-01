"""GTP-U metadata capture; does not retain payloads or map packets to IMSIs."""
from collections import Counter, deque
from pathlib import Path
import re
import subprocess
import threading
import time
import uuid


PACKET = re.compile(
    r"^(\d+\.\d+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)"
    r"\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+): UDP, length (\d+)"
)
DIRECTIONS = ("UL", "DL", "OTHER")

def read_ue_identity(path=None):
    path = Path(path) if path else Path(__file__).resolve().parent.parent / "ue-pod.yaml"
    try:
        text = path.read_text()
        fields = {}
        for name, pattern in (
            ("imsi", r"^    supi:\s*['\"]?imsi-(\d{15})['\"]?\s*$"),
            ("mcc", r"^    mcc:\s*['\"]?(\d{3})['\"]?\s*$"),
            ("mnc", r"^    mnc:\s*['\"]?(\d{2,3})['\"]?\s*$"),
        ):
            match = re.search(pattern, text, re.MULTILINE)
            if not match:
                raise ValueError("Missing UE identity field")
            fields[name] = match.group(1)
        if not fields["imsi"].startswith(fields["mcc"] + fields["mnc"]):
            raise ValueError("UE IMSI does not match its PLMN")
        return {**fields, "source": "ue-pod.yaml", "status": "configured"}
    except (OSError, ValueError):
        return {"status": "unknown", "source": "ue-pod.yaml"}


def parse_packet(line):
    match = PACKET.match(line)
    if not match:
        return None
    timestamp, src, sport, dst, dport, length = match.groups()
    if "2152" not in (sport, dport):
        return None
    direction = "OTHER"
    if src == "127.0.0.1" and dst == "127.0.0.7":
        direction = "UL"
    elif src == "127.0.0.7" and dst == "127.0.0.1":
        direction = "DL"
    return {"timestamp": float(timestamp), "source": src, "source_port": int(sport),
            "destination": dst, "destination_port": int(dport),
            "bytes": int(length), "direction": direction}


class TraceBuffer:
    def __init__(self, limit=500):
        self.lock = threading.Lock()
        self.packets = deque(maxlen=limit)
        self.bins = {}
        self.totals = Counter()
        self.sequence = 0
        self.status = "starting"
        self.message = "Starting GTP-U capture…"
        self.last_seen = None

    def set_status(self, status, message):
        with self.lock:
            self.status, self.message = status, message

    def _prune(self, second):
        for key in list(self.bins):
            if key < second - 59:
                del self.bins[key]

    def add(self, packet, now=None):
        second = int(time.monotonic() if now is None else now)
        with self.lock:
            self.sequence += 1
            packet = dict(packet, id=self.sequence)
            self.packets.append(packet)
            direction = packet["direction"]
            self.totals[direction + "_packets"] += 1
            self.totals[direction + "_bytes"] += packet["bytes"]
            bucket = self.bins.setdefault(second, Counter())
            bucket[direction + "_bytes"] += packet["bytes"]
            bucket[direction + "_packets"] += 1
            self.last_seen = time.time()
            self._prune(second)

    def snapshot(self, now=None):
        second = int(time.monotonic() if now is None else now)
        identity = read_ue_identity()
        with self.lock:
            self._prune(second)
            rates = {}
            for direction in DIRECTIONS:
                size = sum(self.bins.get(s, {}).get(direction + "_bytes", 0)
                           for s in range(second - 4, second + 1))
                count = sum(self.bins.get(s, {}).get(direction + "_packets", 0)
                            for s in range(second - 4, second + 1))
                rates[direction] = {"mbps": size * 8 / 5 / 1e6, "pps": count / 5}
            history = [
                {"seconds_ago": second - s,
                 **{d: self.bins.get(s, {}).get(d + "_bytes", 0) * 8 / 1e6
                    for d in DIRECTIONS}}
                for s in range(second - 59, second + 1)
            ]
            return {"status": self.status, "message": self.message,
                    "last_seen": self.last_seen, "updated": time.time(),
                    "packets": list(self.packets), "totals": dict(self.totals),
                    "rates": rates, "history": history, "buffer_limit": self.packets.maxlen,
                    "capture": "Core pod lo · UDP 2152 · packet metadata only",
                    "ue_identity": identity,
                    "subscriber": "IMSI not identified by this capture"}


class GtpCapture:
    def __init__(self, podman, buffer):
        self.podman = podman
        self.buffer = buffer
        self.stop = threading.Event()
        self.helper = "dpt-gtp-" + uuid.uuid4().hex[:12]
        self.process = None
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        if self.stop.is_set():
            return
        if not self.podman:
            self.buffer.set_status("error", "Podman executable not found.")
            return
        try:
            subprocess.run(
                [self.podman, "run", "-d", "--name", self.helper,
                 "--label", "io.dpt.dashboard-capture=true", "--pod", "open5gs",
                 "--cap-add", "NET_RAW", "--security-opt", "label=disable",
                 "gtpu-mon:0.1", "sleep", "2147483647"],
                capture_output=True, text=True, timeout=30, check=True,
            )
            while not self.stop.is_set():
                self.buffer.set_status("starting", "Opening core-pod GTP-U capture…")
                self.process = subprocess.Popen(
                    [self.podman, "exec", self.helper, "timeout", "45",
                     "tcpdump", "-p", "-i", "lo", "-nn", "-l", "-tt", "-q",
                     "-s", "96", "udp", "port", "2152"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
                for line in self.process.stdout:
                    if self.stop.is_set():
                        break
                    packet = parse_packet(line)
                    if packet:
                        self.buffer.add(packet)
                    elif "listening on lo" in line:
                        self.buffer.set_status("live", "Capture running. Idle is normal without UE traffic.")
                    elif "tcpdump:" in line and "verbose output" not in line:
                        self.buffer.set_status("error", line.strip()[:240])
                code = self.process.wait(timeout=8)
                self.process.stdout.close()
                if code not in (0, 124, 137, 143):
                    self.buffer.set_status("error", "Capture exited; check the core pod and monitor image.")
                    self.stop.wait(3)
        except (OSError, subprocess.SubprocessError):
            self.buffer.set_status("error", "Capture unavailable. Check Podman, the open5gs pod and gtpu-mon:0.1 image.")
        finally:
            self._remove_helper()
            self._reap_process()

    def _reap_process(self):
        if self.process is None:
            return
        try:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass
        finally:
            if self.process.stdout is not None:
                self.process.stdout.close()

    def _remove_helper(self):
        if self.podman:
            try:
                subprocess.run([self.podman, "rm", "-f", self.helper],
                               capture_output=True, timeout=10)
            except (OSError, subprocess.SubprocessError):
                pass

    def close(self):
        self.stop.set()
        self._remove_helper()
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
        if self.thread is not None:
            self.thread.join(timeout=12)
        self.buffer.set_status("stopped", "Capture stopped.")
