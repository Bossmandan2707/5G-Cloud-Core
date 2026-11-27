"""Least-privilege UE-namespace telemetry; no enrollment or remote control."""
import copy
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import psutil
from prometheus_client import CollectorRegistry, Gauge, generate_latest


PROBE_ADDRESS = "1.1.1.1"
PROBE_PORT = 443
PORT = 9108


def read_number(path):
    try:
        text = Path(path).read_text().strip()
        return int(text) if text != "max" else None
    except (OSError, ValueError):
        return None


def read_ip(*args):
    result = subprocess.run(["ip", "-j", *args], capture_output=True, text=True,
                            timeout=2, check=True)
    value = json.loads(result.stdout)
    if not isinstance(value, list):
        raise ValueError("Invalid ip output")
    return value


def safe_network_metadata(rows, keys):
    return [{key: row[key] for key in keys if key in row}
            for row in rows if isinstance(row, dict)]


def counter_rates(current, previous, elapsed):
    if previous is None or elapsed <= 0:
        return {"rx_bps": None, "tx_bps": None, "counter_reset": False}
    reset = any(current[key] < previous[key] for key in ("rx_bytes", "tx_bytes"))
    return {"rx_bps": None if reset else (current["rx_bytes"] - previous["rx_bytes"]) / elapsed,
            "tx_bps": None if reset else (current["tx_bytes"] - previous["tx_bytes"]) / elapsed,
            "counter_reset": reset}


def bound_probe(source_ip, interface):
    result = {"target": f"{PROBE_ADDRESS}:{PROBE_PORT}", "source_ip": source_ip,
              "interface": interface, "checked_at": time.time(),
              "up": None, "latency_ms": None, "route_verified": False}
    try:
        ipaddress.IPv4Address(source_ip)
        route = read_ip("route", "get", PROBE_ADDRESS, "from", source_ip)
        if not route or route[0].get("dev") != interface:
            result["reason"] = "Skipped: source route does not use the UE tunnel."
            return result
        result["route_verified"] = True
        start = time.monotonic()
        with socket.create_connection((PROBE_ADDRESS, PROBE_PORT), timeout=3,
                                      source_address=(source_ip, 0)) as connection:
            if connection.getsockname()[0] != source_ip:
                raise OSError("Unexpected probe source")
        result.update(up=True, latency_ms=(time.monotonic() - start) * 1000,
                      reason="TCP handshake through the UE-source route.")
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        result.update(up=False if result["route_verified"] else None,
                      reason="TCP probe failed." if result["route_verified"]
                      else "Skipped: UE-source route could not be verified.")
    return result


def metrics(snapshot):
    registry = CollectorRegistry()
    def gauge(name, help_text, value):
        if isinstance(value, (int, float)):
            Gauge(name, help_text, registry=registry).set(value)
    gauge("ue_mdm_agent_up", "Agent heartbeat is fresh", int(snapshot.get("status") == "ok"))
    gauge("ue_mdm_agent_uptime_seconds", "Telemetry agent process uptime", snapshot.get("uptime_seconds"))
    resources = snapshot.get("agent_resources", {})
    gauge("ue_mdm_agent_cpu_percent", "Agent process CPU, not UE process CPU", resources.get("cpu_percent"))
    gauge("ue_mdm_agent_rss_bytes", "Agent process resident memory", resources.get("rss_bytes"))
    tunnel = snapshot.get("tunnel", {})
    gauge("ue_mdm_tunnel_admin_up", "UE tunnel administrative state", int(bool(tunnel.get("admin_up"))))
    probe = snapshot.get("probe", {})
    if probe.get("up") is not None:
        gauge("ue_mdm_probe_up", "Fixed TCP probe with verified UE-source route", int(probe["up"]))
    gauge("ue_mdm_probe_latency_ms", "UE-source TCP probe latency", probe.get("latency_ms"))
    rx = Gauge("ue_mdm_namespace_rx_bytes", "Shared UE namespace received bytes", ["interface"], registry=registry)
    tx = Gauge("ue_mdm_namespace_tx_bytes", "Shared UE namespace transmitted bytes", ["interface"], registry=registry)
    for row in snapshot.get("interfaces", []):
        name = row["name"]
        if re.fullmatch(r"(?:eth\d+|lo|uesimtun\d+)", name):
            rx.labels(name).set(row["counters"]["rx_bytes"])
            tx.labels(name).set(row["counters"]["tx_bytes"])
    return generate_latest(registry)


class Agent:
    def __init__(self):
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.started = time.monotonic()
        self.last_sample = None
        self.previous = {}
        self.previous_time = None
        self.last_probe = None
        self.probe_time = None
        self.process = psutil.Process()
        self.process.cpu_percent()
        imsi = os.getenv("UE_MDM_IMSI", "")
        self.identity = imsi if re.fullmatch(r"\d{15}", imsi) else None
        self.data = {"status": "starting", "interfaces": [], "tunnel": {}, "probe": {}}

    def sample(self):
        now = time.monotonic()
        elapsed = now - self.previous_time if self.previous_time is not None else 0
        counters = psutil.net_io_counters(pernic=True)
        addresses, stats = psutil.net_if_addrs(), psutil.net_if_stats()
        interfaces = []
        previous = {}
        for name, counter in counters.items():
            if not re.fullmatch(r"(?:eth\d+|lo|uesimtun\d+)", name):
                continue
            totals = {"rx_bytes": counter.bytes_recv, "tx_bytes": counter.bytes_sent,
                      "rx_packets": counter.packets_recv, "tx_packets": counter.packets_sent,
                      "rx_errors": counter.errin, "tx_errors": counter.errout,
                      "rx_dropped": counter.dropin, "tx_dropped": counter.dropout}
            ips = [a.address for a in addresses.get(name, [])
                   if a.family in (socket.AF_INET, socket.AF_INET6)]
            interfaces.append({"name": name, "admin_up": bool(stats.get(name) and stats[name].isup),
                               "mtu": stats[name].mtu if name in stats else None,
                               "addresses": ips, "counters": totals,
                               "rates": counter_rates(totals, self.previous.get(name), elapsed)})
            previous[name] = totals
        tunnel = next((row for row in interfaces if row["name"].startswith("uesimtun")), None)
        source_ip = next((ip for ip in (tunnel or {}).get("addresses", []) if ":" not in ip), None)
        probe_identity = (source_ip, (tunnel or {}).get("name"), bool(tunnel and tunnel["admin_up"]))
        last_identity = getattr(self, "probe_identity", None)
        if self.probe_time is None or now - self.probe_time >= 30 or probe_identity != last_identity:
            if source_ip and tunnel["admin_up"]:
                self.last_probe = bound_probe(source_ip, tunnel["name"])
            else:
                self.last_probe = {"up": None, "latency_ms": None, "checked_at": time.time(),
                                   "source_ip": source_ip, "route_verified": False,
                                   "target": f"{PROBE_ADDRESS}:{PROBE_PORT}",
                                   "reason": "Skipped: UE tunnel is unavailable or down."}
            self.probe_time, self.probe_identity = now, probe_identity
        routing_error = None
        try:
            routes = safe_network_metadata(read_ip("route", "show", "table", "all"),
                                           ("dst", "dev", "gateway", "table", "prefsrc"))
            rules = safe_network_metadata(read_ip("rule"), ("priority", "src", "table"))
        except (OSError, ValueError, subprocess.SubprocessError):
            routes, rules = [], []
            routing_error = "Route metadata unavailable."
        data = {
            "schema_version": 1, "status": "ok", "collected_at": time.time(),
            "lab_name": os.getenv("LAB_NAME", "Dan Powell Technologies")[:100],
            "configured_imsi": self.identity,
            "scope": "Shared simulated UE-pod network namespace; not a physical handset.",
            "interfaces": interfaces,
            "tunnel": {"name": tunnel["name"] if tunnel else None,
                       "admin_up": bool(tunnel and tunnel["admin_up"]), "ip": source_ip},
            "probe": self.last_probe, "routes": routes, "rules": rules,
            "routing_error": routing_error,
            "agent_resources": {"scope": "Telemetry agent only, not UE container resources",
                                "cpu_percent": self.process.cpu_percent(),
                                "rss_bytes": self.process.memory_info().rss,
                                "cgroup_memory_bytes": read_number("/sys/fs/cgroup/memory.current"),
                                "cgroup_memory_limit_bytes": read_number("/sys/fs/cgroup/memory.max")},
            "unsupported": ["Battery state", "GPS/location", "Physical RF RSRP/RSRQ/SINR",
                            "Mobile OS enrollment/compliance or remote control"],
        }
        with self.lock:
            self.data = data
            self.last_sample = time.monotonic()
        self.previous, self.previous_time = previous, now

    def snapshot(self):
        with self.lock:
            data = copy.deepcopy(self.data)
            age = time.monotonic() - self.last_sample if self.last_sample is not None else None
        data["sample_age_seconds"] = age
        data["uptime_seconds"] = time.monotonic() - self.started
        if age is not None and age > 20:
            data["status"] = "stale"
        return data

    def run(self):
        while not self.stop.is_set():
            try:
                self.sample()
            except (OSError, ValueError, KeyError, psutil.Error):
                with self.lock:
                    self.data["status"] = "error"
            self.stop.wait(5)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=12)


def make_handler(agent):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            path = self.path.split("?", 1)[0]
            sample = agent.snapshot()
            status = 200
            if path == "/telemetry":
                body, content_type = json.dumps(sample, allow_nan=False).encode(), "application/json"
            elif path == "/healthz":
                status = 200 if sample["status"] == "ok" else 503
                body, content_type = json.dumps({"status": sample["status"],
                                                "sample_age_seconds": sample["sample_age_seconds"]}).encode(), "application/json"
            elif path == "/metrics":
                body, content_type = metrics(sample), "text/plain; version=0.0.4; charset=utf-8"
            else:
                self.send_error(404)
                return
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass
    return Handler


def main():
    agent = Agent()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), make_handler(agent))
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    try:
        agent.start()
        print(f"UE MDM telemetry: pod loopback 127.0.0.1:{PORT}", flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        agent.close()


if __name__ == "__main__":
    main()
