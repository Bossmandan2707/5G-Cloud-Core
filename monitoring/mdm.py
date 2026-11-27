"""Combine the UE-pod agent with whitelisted UERANSIM and container observations."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import copy
import ipaddress
import json
import math
import re
import subprocess
import threading
import time

import yaml
from prometheus_client import CollectorRegistry, Gauge, generate_latest

from gtp_trace import read_ue_identity


REQUEST = ('import urllib.request; '
           'r=urllib.request.urlopen("http://127.0.0.1:9108/telemetry",timeout=4); '
           'print(r.read(262144).decode())')
STATUS_FIELDS = ("cm-state", "rm-state", "mm-state", "5u-state", "sim-inserted",
                 "selected-plmn", "current-plmn", "current-tac")


def fields(value, names):
    if not isinstance(value, dict):
        return {}
    return {key: value[key][:160] if isinstance(value[key], str) else value[key]
            for key in names if key in value and
            (value[key] is None or isinstance(value[key], (str, int, float, bool)))
            and (not isinstance(value[key], float) or math.isfinite(value[key]))}


def native_status(text):
    value = yaml.safe_load(text)
    if not isinstance(value, dict):
        raise ValueError("Native status unavailable")
    return fields(value, STATUS_FIELDS)


def native_sessions(text):
    value = yaml.safe_load(text)
    if value is None:
        return []
    if not isinstance(value, dict):
        raise ValueError("Native sessions unavailable")
    sessions = []
    for key, row in value.items():
        match = re.fullmatch(r"PDU Session(\d+)", str(key))
        if match and isinstance(row, dict) and len(sessions) < 16:
            sessions.append({"id": int(match.group(1)), **fields(
                row, ("state", "session-type", "apn", "address", "emergency", "data-pending"))})
    return sessions


def clean_agent(value):
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("Unsupported telemetry schema")
    output = fields(value, ("schema_version", "status", "lab_name", "configured_imsi",
                            "collected_at", "sample_age_seconds", "uptime_seconds", "routing_error"))
    if not re.fullmatch(r"\d{15}", str(output.get("configured_imsi", ""))):
        output["configured_imsi"] = None
    output["tunnel"] = fields(value.get("tunnel"), ("name", "admin_up", "ip"))
    output["probe"] = fields(value.get("probe"), (
        "target", "source_ip", "interface", "checked_at", "up", "latency_ms", "route_verified", "reason"))
    output["agent_resources"] = fields(value.get("agent_resources"), (
        "cpu_percent", "rss_bytes", "cgroup_memory_bytes", "cgroup_memory_limit_bytes"))
    output["interfaces"] = []
    for row in value.get("interfaces", [])[:16]:
        if not isinstance(row, dict) or not re.fullmatch(r"(?:eth\d+|lo|uesimtun\d+)", str(row.get("name", ""))):
            continue
        addresses = []
        for address in row.get("addresses", [])[:16]:
            try:
                ipaddress.ip_address(address.split("%")[0])
                addresses.append(address[:100])
            except (ValueError, TypeError, AttributeError):
                continue
        output["interfaces"].append({
            **fields(row, ("name", "admin_up", "mtu")), "addresses": addresses,
            "counters": fields(row.get("counters"), ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                                                   "rx_errors", "tx_errors", "rx_dropped", "tx_dropped")),
            "rates": fields(row.get("rates"), ("rx_bps", "tx_bps", "counter_reset")),
        })
    output["routes"] = [fields(row, ("dst", "dev", "gateway", "table", "prefsrc"))
                        for row in value.get("routes", [])[:128]]
    output["rules"] = [fields(row, ("priority", "src", "table"))
                       for row in value.get("rules", [])[:64]]
    return output


def percent(value):
    try:
        result = float(str(value).rstrip("%"))
        return result if math.isfinite(result) else None
    except (TypeError, ValueError):
        return None


class MdmMonitor:
    def __init__(self, podman):
        self.podman = podman
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.history = deque(maxlen=120)
        self.last_agent_sample = None
        self.data = {"updated": None, "agent": None, "radio": {}, "sessions": [],
                     "resources": {}, "errors": ["Waiting for UE telemetry."],
                     "radio_updated": None}

    def run_command(self, *args):
        if not self.podman:
            raise OSError("Podman unavailable")
        result = subprocess.run([self.podman, *args], capture_output=True, text=True,
                                timeout=12, check=True)
        if len(result.stdout) > 262144:
            raise ValueError("Observation too large")
        return result.stdout

    def collect_agent(self):
        return clean_agent(json.loads(self.run_command("exec", "ue-mdm", "python", "-c", REQUEST)))

    def collect_radio(self, imsi):
        if not re.fullmatch(r"\d{15}", imsi or ""):
            raise ValueError("Configured UE identity unavailable")
        node = "imsi-" + imsi
        status = native_status(self.run_command("exec", "ue-ue", "nr-cli", node, "--exec", "status"))
        sessions = native_sessions(self.run_command("exec", "ue-ue", "nr-cli", node, "--exec", "ps-list"))
        return status, sessions

    def collect_resources(self):
        state = json.loads(self.run_command("inspect", "--format", "{{json .State}}", "ue-ue"))
        result = {"scope": "UERANSIM UE container only",
                  "state": fields(state, ("Running", "Restarting", "OOMKilled", "ExitCode", "StartedAt", "FinishedAt"))}
        if state.get("Running"):
            rows = json.loads(self.run_command("stats", "--no-stream", "--format", "json", "ue-ue")) or []
            row = next((row for row in rows if row.get("name") == "ue-ue"), {})
            result.update(cpu_percent=percent(row.get("cpu_percent")),
                          memory_percent=percent(row.get("mem_percent")),
                          memory_usage=str(row.get("mem_usage", ""))[:100],
                          pids=row.get("pids"))
        return result

    def sample(self):
        identity = read_ue_identity()
        data = {"updated": time.time(), "identity": identity, "agent": None,
                "radio": {}, "sessions": [], "resources": {}, "errors": [], "radio_updated": None}
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs = {"agent": pool.submit(self.collect_agent),
                    "radio": pool.submit(self.collect_radio, identity.get("imsi")),
                    "resources": pool.submit(self.collect_resources)}
            for kind, future in jobs.items():
                try:
                    value = future.result()
                    if kind == "radio":
                        data["radio"], data["sessions"] = value
                        data["radio_updated"] = time.time()
                    else:
                        data[kind] = value
                except (OSError, ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError, subprocess.SubprocessError):
                    data["errors"].append({"agent": "UE-pod telemetry agent unavailable.",
                                           "radio": "Native UE registration/session status unavailable.",
                                           "resources": "UE-container resources unavailable."}[kind])
        data["updated"] = time.time()
        with self.lock:
            agent = data["agent"]
            if agent and agent.get("status") == "ok" and agent.get("collected_at") != self.last_agent_sample:
                tunnel = next((r for r in agent["interfaces"] if r["name"].startswith("uesimtun")), {})
                self.history.append({"at": agent.get("collected_at"),
                                     "rx_bps": tunnel.get("rates", {}).get("rx_bps"),
                                     "tx_bps": tunnel.get("rates", {}).get("tx_bps"),
                                     "latency_ms": agent.get("probe", {}).get("latency_ms"),
                                     "ue_cpu_percent": data["resources"].get("cpu_percent")})
                self.last_agent_sample = agent.get("collected_at")
            self.data = data

    def snapshot(self, now=None):
        now = time.time() if now is None else now
        with self.lock:
            data = copy.deepcopy(self.data)
            data["history"] = list(self.history)
        data["stale"] = data["updated"] is None or now - data["updated"] > 35
        agent = data["agent"]
        data["agent_fresh"] = bool(not data["stale"] and agent and agent.get("status") == "ok"
                                  and isinstance(agent.get("sample_age_seconds"), (int, float))
                                  and 0 <= agent["sample_age_seconds"] + max(0, now - data["updated"]) <= 20)
        data["native_fresh"] = bool(not data["stale"] and data.get("radio_updated")
                                   and now - data["radio_updated"] <= 35)
        checked = (agent or {}).get("probe", {}).get("checked_at")
        data["probe_fresh"] = bool(data["agent_fresh"] and isinstance(checked, (int, float))
                                   and 0 <= now - checked <= 65)
        data["warnings"] = []
        if not data["agent_fresh"]:
            data["warnings"].append("Agent data unavailable or stale; do not interpret cached counters as live.")
        if data["agent_fresh"] and not agent.get("tunnel", {}).get("admin_up"):
            data["warnings"].append("UE tunnel is missing or administratively down.")
        if data["agent_fresh"] and agent.get("probe", {}).get("up") is False:
            data["warnings"].append("Latest UE-source TCP probe failed.")
        if data["native_fresh"] and data["radio"].get("rm-state") != "RM-REGISTERED":
            data["warnings"].append("UE is not currently registered.")
        if agent and agent.get("configured_imsi") != data.get("identity", {}).get("imsi"):
            data["warnings"].append("Agent identity metadata differs from the configured UE; rebuild/redeploy its environment.")
        data["unsupported"] = ["Battery", "GPS/location", "Physical RF signal measurements",
                               "Mobile OS enrollment/compliance and remote control"]
        return data

    def render_metrics(self):
        data = self.snapshot()
        registry = CollectorRegistry()
        def gauge(name, description, value):
            if isinstance(value, (int, float)) and math.isfinite(value):
                Gauge(name, description, registry=registry).set(value)
        gauge("ue_mdm_agent_up", "UE-pod agent telemetry is fresh", int(data["agent_fresh"]))
        gauge("ue_mdm_native_status_available", "Native UE state is fresh", int(data["native_fresh"]))
        if data["native_fresh"]:
            gauge("ue_mdm_registered", "Live native UE RM-REGISTERED state", int(data["radio"].get("rm-state") == "RM-REGISTERED"))
            gauge("ue_mdm_active_pdu_sessions", "Live active PDU sessions", sum(s.get("state") == "PS-ACTIVE" for s in data["sessions"]))
        if data["agent_fresh"]:
            agent = data["agent"]
            gauge("ue_mdm_tunnel_admin_up", "UE tunnel administrative state", int(bool(agent["tunnel"].get("admin_up"))))
            gauge("ue_mdm_agent_rss_bytes", "Telemetry-agent resident memory, not UE container", agent["agent_resources"].get("rss_bytes"))
            gauge("ue_mdm_agent_cpu_percent", "Telemetry-agent process CPU, not UE container", agent["agent_resources"].get("cpu_percent"))
            probe = agent["probe"]
            if data["probe_fresh"] and probe.get("up") is not None:
                gauge("ue_mdm_probe_up", "Latest fixed TCP probe with UE-bound source", int(probe["up"]))
            if data["probe_fresh"]:
                gauge("ue_mdm_probe_latency_ms", "Latest fixed TCP handshake latency", probe.get("latency_ms"))
        if not data["stale"]:
            gauge("ue_mdm_ue_cpu_percent", "UERANSIM container CPU percent", data["resources"].get("cpu_percent"))
            gauge("ue_mdm_ue_memory_percent", "UERANSIM container memory percent", data["resources"].get("memory_percent"))
        return generate_latest(registry)

    def run(self):
        while not self.stop.is_set():
            try:
                self.sample()
            except (OSError, ValueError, TypeError):
                with self.lock:
                    self.data["errors"] = ["UE telemetry sampling failed."]
            self.stop.wait(10)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=30)
