"""Read-only IMS readiness observations; never infer a VoNR call from a listener."""
import copy
import json
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from interfaces import parse_sockets


ROOT = Path(__file__).resolve().parent.parent
PREPARATION = Path.home() / ".config/dan-powell-technologies/ims-lab/preparation.json"
ACTIVATION = PREPARATION.with_name("activation-progress.json")
BUILD_STATUS = PREPARATION.with_name("image-build-status.json")
CALL_PREPARATION = PREPARATION.parent.parent / "ims-client/call-preparation.json"
PRIVATE = PREPARATION.parent.parent
MAP_CONTAINERS = {
    "ue": "ue-ue", "gnb": "open5gs-gnb", "agent": "dpt-ims-ue-client",
    **{name: "open5gs-" + name for name in
       ("amf", "smf", "upf", "pcf", "bsf", "scp", "ausf", "udm", "udr", "nrf")},
    **{name: "dpt-ims-" + name for name in
       ("pcscf", "icscf", "scscf", "pyhss", "dns", "rtpengine")},
    "b2bua": "dpt-sip-control-test",
}


def outbound_gate(text):
    values = re.findall(r"^\s*DPT_OUTBOUND_ARMED=(\S+)\s*$", text, re.M)
    if values == ["0"]:
        return "disarmed"
    if values == ["1"]:
        return "armed"
    return "unknown"


def network_map(config, states):
    return {
        "states": {key: "unknown" if states is None else states.get(container, "not deployed")
                   for key, container in MAP_CONTAINERS.items()},
        "core_ims_address": config["network"]["core_ims_ip"],
        "ue_pool": config["network"]["ims_ue_subnet"],
        "b2bua": {"address": "10.90.0.24", "port": 5060, "outbound_gate": "unknown",
                  "gate_observed_at": None},
        "interconnect": {
            "label": "Telnix Los Angeles Interconnect", "provider": "Telnyx",
            "transport": "SIP / TLS", "port": 5061,
            "scope": "User-defined diagram label; carrier point of presence not verified.",
        },
        "preflight": None, "last_call": None,
        "scope": "Configured connections, not live link or end-to-end call verification.",
    }


def preflight_summary(path=CALL_PREPARATION):
    try:
        if path.stat().st_size > 128 * 1024:
            return None
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            return None
        blocker = value.get("blocking_component")
        events = value.get("ue_events", [])
        if not isinstance(events, list):
            events = []
        return {
            "passed": value.get("passed") if type(value.get("passed")) is bool else None,
            "protected_registration_observed": any(
                isinstance(line, str) and line.startswith("DPT_REGISTERED protected=true")
                for line in events),
            "blocker": ("P-CSCF registered-contact lookup"
                        if isinstance(blocker, str) and blocker.startswith("P-CSCF") else None),
            "recorded_at": path.stat().st_mtime,
            "scope": "Saved preflight report, not a current registration or live call state.",
        }
    except (OSError, ValueError, TypeError):
        return None


def topology(path=ROOT / "ims/topology.yaml"):
    value = yaml.safe_load(Path(path).read_text())
    return {"realm": value["realm"], "sip_host": value.get("sip_host", value["realm"]), "network": {
        key: value["network"].get(key) for key in ("name", "display_name", "subnet", "core_ims_ip", "ims_ue_subnet")},
        "services": {name: {key: row[key] for key in ("address", "port", "protocol")}
                     for name, row in value["services"].items()},
        "activation_gates": list(value["activation_gates"]),
        "minimum_vm_memory_mib": value["minimum_vm_memory_mib"],
        "recommended_vm_memory_mib": value["recommended_vm_memory_mib"]}


def saved_call(private=None):
    """Read bounded known-location artifacts; never return raw report data."""
    from ims.sip_trace import messages
    private = PRIVATE if private is None else Path(private)
    try:
        pointer = private / "ims-client/latest-end-to-end-path"
        if pointer.stat().st_size > 4096:
            return None
        folder = Path(pointer.read_text().strip()).resolve()
        if folder.parent != (private / "traces").resolve():
            return None
        path = folder / "end-to-end-result.json"
        if path.resolve().parent != folder or path.stat().st_size > 128 * 1024:
            return None
        value = json.loads(path.read_text())
        ue = value.get("ue_call") or {}
        results = value.get("gateway_dial_results") or []
        answered = any(r.get("status") == "ANSWER" and str(r.get("cause")) == "16"
                       for r in results if isinstance(r, dict))
        passed = (ue.get("answered") is True and ue.get("final_status") == 200
                  and ue.get("release_ok") is True and answered)
        events = []
        trace = folder / "sip-trace.json"
        if trace.exists() and trace.resolve().parent == folder and trace.stat().st_size < 1024 * 1024:
            raw = json.loads(trace.read_text())
            for event in raw.get("events", [])[:300]:
                if event.get("point") != "ue" or not isinstance(event.get("message"), str):
                    continue
                events.extend(messages((event["message"] + "\n\n").encode(), "ue"))
        return {"passed": bool(passed), "recorded_at": path.stat().st_mtime,
                "answered": ue.get("answered") is True,
                "final_status": ue.get("final_status") if type(ue.get("final_status")) is int else None,
                "release_ok": ue.get("release_ok") is True,
                "gateway_answer": answered,
                "gateway_disarmed": value.get("gateway_disarmed") is True,
                "registration_preserved": value.get("registration_preserved") is True,
                "ue_trace": [{"start_line": e["start_line"], "cseq": e["cseq"],
                              "message": e["message"]} for e in events],
                "scope": "Saved UE-to-Telnyx signaling evidence, not a live call or audio measurement."}
    except (OSError, ValueError, TypeError, AttributeError):
        return None


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
            "prepared": prepared, "realm": config["realm"], "sip_host": config.get("sip_host", config["realm"]),
            "network": config["network"],
            "network_map": network_map(config, states),
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
                     "activation_gates": [], "memory": {}, "network": {}, "realm": None,
                     "network_map": network_map(topology(), None)}

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
        data["network_map"]["preflight"] = preflight_summary()
        data["network_map"]["last_call"] = saved_call()
        if states and states.get("dpt-sip-control-test") == "running":
            try:
                text = self.command("exec", "dpt-sip-control-test", "asterisk", "-rx",
                                    "dialplan show globals")
                data["network_map"]["b2bua"].update(
                    outbound_gate=outbound_gate(text), gate_observed_at=time.time())
            except (OSError, subprocess.SubprocessError):
                data["errors"].append("B2BUA arming state unavailable; no arming-state claim.")
        data["activation"] = {}
        try:
            progress = json.loads(ACTIVATION.read_text())
            data["activation"] = {key: progress[key] for key in (
                "vm_memory_mib", "backup_verified", "existing_core_restarted",
                "imsi", "msisdn", "sip_host") if key in progress}
        except (OSError, ValueError):
            pass
        try:
            build = json.loads(BUILD_STATUS.read_text())
            data["activation"]["image_build_state"] = build.get("state", "unknown")
        except (OSError, ValueError):
            data["activation"]["image_build_state"] = "not observed"
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
            if "network_map" in data:
                data["network_map"]["states"] = {
                    key: "stale" for key in data["network_map"]["states"]}
                data["network_map"]["b2bua"]["outbound_gate"] = "stale"
                data["network_map"]["b2bua"]["gate_observed_at"] = None
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
