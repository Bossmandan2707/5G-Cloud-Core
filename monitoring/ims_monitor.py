"""Read-only IMS readiness observations; never infer a VoNR call from a listener."""
import copy
import json
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from interfaces import parse_sockets


ROOT = Path(__file__).resolve().parent.parent
PREPARATION = Path.home() / ".config/dan-powell-technologies/ims-lab/preparation.json"


def topology(path=ROOT / "ims/topology.yaml"):
    value = yaml.safe_load(Path(path).read_text())
    return {"realm": value["realm"], "network": {
        key: value["network"][key] for key in ("name", "subnet", "core_ims_ip", "ims_ue_subnet")},
        "services": {name: {key: row[key] for key in ("address", "port", "protocol")}
                     for name, row in value["services"].items()},
        "activation_gates": list(value["activation_gates"]),
        "minimum_vm_memory_mib": value["minimum_vm_memory_mib"],
        "recommended_vm_memory_mib": value["recommended_vm_memory_mib"]}


def build_snapshot(config, states, listeners, errors, prepared, now=None):
    rows = []
    for name, endpoint in config["services"].items():
        container = "dpt-ims-" + name
        state = (states or {}).get(container)
        status = "unknown" if states is None else "not deployed" if state is None else state
        bound = None
        if state == "running" and name in listeners:
            bound = any(s["protocol"] == endpoint["protocol"] and s["port"] == endpoint["port"]
                        and s["address"] in (endpoint["address"], "0.0.0.0")
                        for s in listeners[name])
        rows.append({"name": name, "container": container, **endpoint,
                     "container_status": status, "listener_observed": bound,
                     "address_source": "prepared topology; not a discovered UE address"})
    return {"updated": time.time() if now is None else now, "stale": False,
            "prepared": prepared, "realm": config["realm"], "network": config["network"],
            "services": rows, "errors": errors, "activation_gates": config["activation_gates"],
            "memory": {"minimum_mib": config["minimum_vm_memory_mib"],
                       "recommended_mib": config["recommended_vm_memory_mib"]},
            "verification": {
                "ims_aka_registration": None, "n5_policy_authorization": None,
                "voice_qos": None, "bidirectional_rtp": None, "handset_vonr": None},
            "counters": {"registrations": None, "active_calls": None,
                         "diameter_connected_peers": None, "media_packets": None},
            "scope": "Read-only container/listener inventory, not verified IMS or VoNR service."}


class ImsMonitor:
    def __init__(self, podman):
        self.podman = podman
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.data = {"updated": None, "stale": True, "prepared": False, "services": [],
                     "errors": ["Waiting for IMS inventory."], "verification": {}, "counters": {},
                     "activation_gates": [], "memory": {}, "network": {}, "realm": None}

    def command(self, *args):
        if not self.podman:
            raise OSError("Podman unavailable")
        result = subprocess.run([self.podman, *args], capture_output=True, text=True,
                                timeout=5, check=True)
        return result.stdout

    def listener(self, name):
        return parse_sockets(self.command("exec", "dpt-ims-" + name, "ss", "-H", "-lntu"))

    def sample(self):
        config = topology()
        errors, states, listeners = [], None, {}
        try:
            text = self.command("ps", "-a", "--format", "{{.Names}}\t{{.State}}")
            states = dict(line.split("\t", 1) for line in text.splitlines() if "\t" in line)
        except (OSError, subprocess.SubprocessError):
            errors.append("Container inventory unavailable; no running-state claim can be made.")
        if states:
            with ThreadPoolExecutor(max_workers=3) as pool:
                jobs = {name: pool.submit(self.listener, name) for name in config["services"]
                        if states.get("dpt-ims-" + name) == "running"}
                for name, future in jobs.items():
                    try:
                        listeners[name] = future.result()
                    except (OSError, subprocess.SubprocessError):
                        errors.append(name + ": listener observation unavailable.")
        prepared = False
        try:
            metadata = json.loads(PREPARATION.read_text())
            prepared = metadata.get("status") == "prepared-not-activated"
        except (OSError, ValueError):
            pass
        data = build_snapshot(config, states, listeners, errors, prepared)
        with self.lock:
            self.data = data

    def snapshot(self, now=None):
        with self.lock:
            data = copy.deepcopy(self.data)
        now = time.time() if now is None else now
        data["stale"] = data["updated"] is None or now - data["updated"] > 45
        if data["stale"]:
            for row in data["services"]:
                row["container_status"] = "stale"
                row["listener_observed"] = None
        return data

    def run(self):
        while not self.stop.is_set():
            try:
                self.sample()
            except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError):
                with self.lock:
                    self.data["errors"] = ["IMS inventory could not be refreshed."]
                    self.data["updated"] = None
            self.stop.wait(15)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=20)
