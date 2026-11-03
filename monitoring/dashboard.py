"""Local dashboard: .venv/bin/python monitoring/dashboard.py (localhost:8000)."""
import argparse
import json
import platform
import signal
import shutil
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

import app as exporter
from gtp_trace import GtpCapture, TraceBuffer
from interfaces import InterfaceMonitor
from mdm import MdmMonitor


LOCK = threading.Lock()
STATE = {"lab_name": exporter.LAB_NAME, "host": None, "containers": [], "container_error": "Waiting for Podman",
         "container_updated": None}
PODMAN = shutil.which("podman")
if not PODMAN and Path("/opt/podman/bin/podman").is_file():
    PODMAN = "/opt/podman/bin/podman"
HTML = Path(__file__).with_name("dashboard.html").read_bytes()
GTP_HTML = Path(__file__).with_name("gtp.html").read_bytes()
TRACE = TraceBuffer()
INTERFACES_HTML = Path(__file__).with_name("interfaces.html").read_bytes()
INTERFACES = InterfaceMonitor(PODMAN)
MDM_HTML = Path(__file__).with_name("mdm.html").read_bytes()
MDM = MdmMonitor(PODMAN)


def sample_host():
    previous = psutil.net_io_counters()
    previous_time = time.monotonic()
    psutil.cpu_percent()
    while True:
        try:
            cpu_percent = exporter.collect()
            now = time.monotonic()
            net = psutil.net_io_counters()
            elapsed = max(now - previous_time, 0.001)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            host = {
                "label": platform.system() + " host (not the Podman VM)",
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_used": memory.total - memory.available,
                "memory_total": memory.total,
                "disk_percent": disk.percent,
                "load1": psutil.getloadavg()[0],
                "rx_bps": max(0, net.bytes_recv - previous.bytes_recv) / elapsed,
                "tx_bps": max(0, net.bytes_sent - previous.bytes_sent) / elapsed,
                "updated": time.time(),
            }
            with LOCK:
                STATE["host"] = host
                STATE.pop("host_error", None)
            previous, previous_time = net, now
        except Exception as exc:
            with LOCK:
                STATE["host_error"] = type(exc).__name__
        time.sleep(2)


def run_podman(*args):
    result = subprocess.run([PODMAN, *args], capture_output=True, text=True,
                            timeout=15, check=True)
    return result.stdout


def sample_containers():
    while True:
        try:
            if not PODMAN:
                raise RuntimeError("Podman executable not found")
            listing = run_podman("ps", "-a", "--format",
                                 "{{.Names}}\t{{.State}}\t{{.Status}}")
            stats = json.loads(run_podman("stats", "--no-stream", "--format", "json") or "[]")
            if stats is None:
                stats = []
            if not isinstance(stats, list) or any(not isinstance(row, dict) for row in stats):
                raise ValueError("Unexpected Podman statistics format")
            by_name = {row["name"]: row for row in stats}
            rows = []
            for line in listing.splitlines():
                name, state, status = line.split("\t", 2)
                if not (name.startswith("open5gs-") or name in ("ue-ue", "ue-yt", "ue-mdm", "py-monitor")):
                    continue
                if name.endswith("-infra"):
                    continue
                row = by_name.get(name, {})
                rows.append({"name": name, "state": state, "status": status,
                             "cpu": row.get("cpu_percent"),
                             "memory": row.get("mem_usage"),
                             "network": row.get("net_io"),
                             "pids": row.get("pids")})
            with LOCK:
                STATE.update(containers=sorted(rows, key=lambda r: r["name"]),
                             container_error=None, container_updated=time.time())
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
            with LOCK:
                STATE["container_error"] = "Podman metrics unavailable; VM may be stopped or busy."
        time.sleep(8)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/", "/dashboard"):
            body, content_type = HTML, "text/html; charset=utf-8"
        elif path == "/gtp":
            body, content_type = GTP_HTML, "text/html; charset=utf-8"
        elif path == "/api/gtp":
            body = json.dumps(TRACE.snapshot(), allow_nan=False).encode()
            content_type = "application/json"
        elif path == "/interfaces":
            body, content_type = INTERFACES_HTML, "text/html; charset=utf-8"
        elif path == "/api/interfaces":
            body = json.dumps(INTERFACES.snapshot(), allow_nan=False).encode()
            content_type = "application/json"
        elif path == "/mdm":
            body, content_type = MDM_HTML, "text/html; charset=utf-8"
        elif path == "/api/mdm":
            body = json.dumps(MDM.snapshot(), allow_nan=False).encode()
            content_type = "application/json"
        elif path == "/api/snapshot":
            with LOCK:
                body = json.dumps(STATE, allow_nan=False).encode()
            content_type = "application/json"
        elif path == "/metrics":
            body, content_type = generate_latest() + MDM.render_metrics(), CONTENT_TYPE_LATEST
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    capture = GtpCapture(PODMAN, TRACE)

    def terminate(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, terminate)
    for target in (sample_host, sample_containers):
        threading.Thread(target=target, daemon=True).start()
    print(f"{exporter.LAB_NAME} dashboard: http://127.0.0.1:{args.port}", flush=True)
    try:
        capture.start()
        INTERFACES.start()
        MDM.start()
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        capture.close()
        INTERFACES.close()
        MDM.close()


if __name__ == "__main__":
    main()
