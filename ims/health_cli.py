"""Bounded, non-dialing health checks and allowlisted recovery for the saved lab."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import uuid

import psutil
import yaml

from ims import runtime, start_cli
from ims.call_cli import readiness, zero_channels
from ims.call_prep import load_profile

ROOT = Path(__file__).resolve().parent.parent
MACHINE = "podman-machine-default"
NRF = "http://127.0.0.10:7777/nnrf-nfm/v1/nf-instances"
NFS = {"NRF", "AMF", "SMF", "AUSF", "UDM", "UDR", "PCF", "BSF", "SCP"}
GATEWAY = "dpt-sip-control-test"
HTTP = "http://127.0.0.1:8000"
CORRUPTION = re.compile(
    r"XFS.*(?:corrupt|shutting down|unmount and run)|metadata I/O error|"
    r"Failed to write.*Input/output error", re.I)

# All sockets bind explicitly to the current internet PDU address.
# No credentials, application payloads or arbitrary URLs are used.
PROBE = r"""
import json, os, socket, ssl, struct, sys
source = sys.argv[1]
result = {"tcp": False, "https": False, "dns": False}
for host, name in (("1.1.1.1", "one.one.one.one"), ("8.8.8.8", "dns.google")):
    try:
        with socket.create_connection((host, 443), timeout=2,
                                      source_address=(source, 0)) as plain:
            result["tcp"] = True
            with ssl.create_default_context().wrap_socket(plain, server_hostname=name) as stream:
                stream.settimeout(2)
                stream.sendall(("HEAD / HTTP/1.1\r\nHost: " + name
                                + "\r\nConnection: close\r\n\r\n").encode())
                status = stream.recv(256).split(b"\r\n", 1)[0].split()
                result["https"] = len(status) > 1 and status[1].isdigit() and 200 <= int(status[1]) < 400
        if result["https"]:
            break
    except (OSError, ValueError):
        pass
for host in ("1.1.1.1", "8.8.8.8"):
    try:
        ident = os.urandom(2)
        query = ident + struct.pack("!HHHHH", 0x100, 1, 0, 0, 0)
        query += b"\x07example\x03com\x00\x00\x01\x00\x01"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            s.bind((source, 0))
            s.connect((host, 53))
            s.send(query)
            answer = s.recv(4096)
        result["dns"] = (len(answer) >= 12 and answer[:2] == ident
                         and bool(answer[2] & 0x80) and answer[3] & 15 == 0
                         and struct.unpack("!H", answer[6:8])[0] > 0)
        if result["dns"]:
            break
    except OSError:
        pass
print(json.dumps(result))
"""


class HealthError(RuntimeError):
    pass


class DeadlineExceeded(HealthError):
    pass


def metric(text, name):
    values = re.findall(r"^" + re.escape(name) + r"(?:\{[^}\n]*\})?\s+([0-9.eE+-]+)\s*$",
                        text, re.M)
    return sum(float(v) for v in values) if values else None


def disk_corruption(text):
    # Diagnose only the latest kernel boot if the console file contains several.
    return bool(CORRUPTION.search(text.rsplit("Run /init as init process", 1)[-1]))


def internet_binding(current, interfaces):
    documents = list(yaml.safe_load_all((ROOT / "open5gs-pod.yaml").read_text()))
    config = next(d["data"] for d in documents if d.get("kind") == "ConfigMap")
    sessions = yaml.safe_load(config["smf.yaml"])["smf"]["session"]
    subnet = next((s["subnet"] for s in sessions if s.get("dnn") == "internet"),
                  sessions[0]["subnet"])
    # Reuse the tested exact-address interface selector, not a tunnel index.
    session = current.get("internet", {})
    selected = runtime.select_ims_tunnel(
        {"ims": session, "internet": current.get("ims", {})}, interfaces, subnet)
    return selected


@contextmanager
def lock(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise HealthError("Another call or repair is active; no disruptive repair attempted")
        yield
    finally:
        os.close(fd)


class Runner:
    def __init__(self, scope, repair=True, timeout=360, json_output=False):
        self.scope, self.repair = scope, repair
        self.deadline = time.monotonic() + timeout
        self.json_output = json_output
        self.actions = []
        self.checks = {}
        self.restore_ims = False

    def progress(self, message):
        print(message, file=sys.stderr if self.json_output else sys.stdout, flush=True)

    def remaining(self, maximum=15):
        value = self.deadline - time.monotonic()
        if value <= 0:
            raise DeadlineExceeded("Recovery deadline reached; no further actions attempted")
        return min(maximum, value)

    def command(self, args, label, maximum=15):
        self.remaining()
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               timeout=self.remaining(maximum))
        except subprocess.TimeoutExpired:
            raise HealthError(label + " timed out")
        if r.returncode:
            raise HealthError(label + " failed (code " + str(r.returncode) + ")")
        if len(r.stdout) > 2 * 1024 * 1024:
            raise HealthError(label + " returned oversized diagnostics")
        return r.stdout

    def podman(self, *args, label="Podman check", maximum=15):
        return self.command(["podman", *args], label, maximum)

    def engine(self):
        self.progress("CHECK VM and saved lab connection")
        if os.environ.get("CONTAINER_HOST") or os.environ.get("CONTAINER_CONNECTION"):
            raise HealthError("Podman connection environment override set; refusing an unknown engine")
        connections = json.loads(self.podman("system", "connection", "list", "--format", "json"))
        if not any(c["Name"] == MACHINE and c["Default"] for c in connections):
            raise HealthError("The saved lab connection must be default; refusing another VM")
        machine = json.loads(self.podman("machine", "inspect", MACHINE))[0]
        if machine.get("Rootful"):
            raise HealthError("Saved lab is expected to remain rootless; mode will not be changed")
        if machine["State"] != "running":
            if not self.repair:
                raise HealthError("Saved VM is stopped")
            self.progress("REPAIR start existing VM (no reinitialization)")
            self.podman("machine", "start", MACHINE, label="VM startup", maximum=100)
            self.actions.append("started saved VM")
        try:
            self.podman("info", "--format", "{{.Host.Hostname}}", label="VM engine", maximum=10)
        except HealthError:
            socket_path = machine.get("ConnectionInfo", {}).get("PodmanSocket", {}).get("Path")
            console = Path(socket_path).with_name(MACHINE + ".log") if socket_path else None
            if console and console.is_file():
                with console.open("rb") as source:
                    source.seek(max(0, console.stat().st_size - 2 * 1024 * 1024))
                    text = source.read().decode(errors="replace")
                if disk_corruption(text):
                    raise HealthError("VM disk corruption detected. Offline backup/clone recovery required; "
                                      "no reset, repeated restart or log discard attempted")
            raise HealthError("Saved VM engine is unreachable; no forced restart or disk changes attempted")
        self.checks["engine"] = True

    def containers(self):
        self.progress("CHECK saved core, IMS and UE containers")
        listing = self.podman("ps", "-a", "--format", "{{.Names}}\t{{.State}}")
        states = dict(line.split("\t", 1) for line in listing.splitlines() if "\t" in line)
        required = runtime.SERVICES if self.scope != "internet" else tuple(
            n for n in runtime.SERVICES if not n.startswith("dpt-ims-"))
        for name in required:
            self.remaining()
            if name not in states:
                raise HealthError("Saved container missing: " + name + "; no recreation attempted")
            if states[name] != "running":
                if not self.repair:
                    raise HealthError("Container not running: " + name)
                self.progress("REPAIR start " + name)
                self.podman("start", name, label="Start " + name, maximum=35)
                self.actions.append("started " + name)
        self.checks["saved_containers"] = True

    def nrf_get(self, suffix=""):
        return json.loads(self.podman(
            "exec", "open5gs-nrf", "curl", "-fsS", "--http2-prior-knowledge",
            "--max-time", "4", NRF + suffix, label="NRF live registry", maximum=8))

    def core(self):
        self.progress("CHECK live NRF registrations, N4 and N2")
        items = self.nrf_get().get("_links", {}).get("items", [])
        if not isinstance(items, list) or len(items) > 64:
            raise HealthError("Unexpected NRF registry response")
        identifiers = [str(uuid.UUID(row["href"].rsplit("/", 1)[-1])) for row in items]
        with ThreadPoolExecutor(max_workers=3) as pool:
            profiles = list(pool.map(lambda ident: self.nrf_get("/" + ident), identifiers))
        registered = {p.get("nfType") for p in profiles if p.get("nfStatus") == "REGISTERED"}
        missing = NFS - registered
        if missing:
            raise HealthError("NF registrations missing: " + ", ".join(sorted(missing)))
        metrics = self.podman("exec", "open5gs-smf", "curl", "-fsS", "--max-time", "4",
                              "http://127.0.0.4:9090/metrics", label="SMF live metrics", maximum=8)
        peers = metric(metrics, "pfcp_peers_active")
        if peers is None or peers < 1:
            raise HealthError("No active SMF/UPF PFCP peer")
        nodes = self.podman("exec", "open5gs-gnb", "nr-cli", "--dump", label="gNB instances")
        names = [n.strip() for n in nodes.splitlines()
                 if re.fullmatch(r"UERANSIM-gnb-[A-Za-z0-9-]+", n.strip())]
        if len(names) != 1:
            raise HealthError("Expected one saved gNB control instance")
        radio = self.podman("exec", "open5gs-gnb", "nr-cli", names[0], "-e", "status",
                            label="gNB current NGAP state")
        if yaml.safe_load(radio).get("is-ngap-up") is not True:
            raise HealthError("gNB NGAP association is not up")
        self.checks["core"] = {"registered_nfs": sorted(registered), "pfcp_peers": peers,
                               "ngap_up": True}

    def wait(self, operation, seconds, label):
        deadline = min(self.deadline, time.monotonic() + seconds)
        last = None
        while time.monotonic() < deadline:
            try:
                return operation()
            except DeadlineExceeded:
                raise
            except (HealthError, OSError, ValueError, subprocess.SubprocessError) as error:
                last = type(error).__name__
                time.sleep(min(2, self.remaining(2)))
        raise HealthError(label + " did not become ready (" + str(last) + ")")

    def internet(self):
        self.progress("CHECK real UE-source internet path, HTTPS and DNS")
        current = runtime.ue_sessions()
        interfaces = json.loads(self.podman("exec", "ue-ue", "ip", "-j", "-4", "address", "show"))
        try:
            binding = internet_binding(current, interfaces)
        except (ValueError, RuntimeError):
            self.checks["internet"] = {"ready": False, "reason": "PDU/tunnel mapping unavailable"}
            return False
        route = json.loads(self.podman(
            "exec", "ue-ue", "ip", "-j", "route", "get", "1.1.1.1", "from", binding["address"]))
        route_ok = len(route) == 1 and route[0].get("dev") == binding["interface"]
        if not route_ok:
            self.checks["internet"] = {**binding, "ready": False, "reason": "Source route mismatch"}
            return False
        result = json.loads(self.podman("exec", "ue-mdm", "python3", "-c", PROBE,
                                        binding["address"], label="UE-source probes", maximum=25))
        ready = all(result.get(key) is True for key in ("tcp", "https", "dns"))
        self.checks["internet"] = {**binding, **result, "ready": ready}
        return ready

    def reconnect(self):
        if not self.repair:
            raise HealthError("UE internet path failed; read-only mode made no changes")
        previous = self.checks.get("internet", {})
        if previous.get("tcp") is True:
            raise HealthError("UE TCP works but DNS/HTTPS failed; no speculative radio or DNS changes")
        # Do not restart the radio for a host/VM upstream outage.
        probe = ("import socket; s=socket.create_connection(('1.1.1.1',443),timeout=3); s.close()")
        self.podman("exec", "ue-mdm", "python3", "-c", probe,
                     label="Pod uplink before radio repair", maximum=8)
        with lock(runtime.CLIENT / "call-cli.lock"):
            state_path = runtime.STATE / "status.json"
            if state_path.exists() and json.loads(state_path.read_text()).get("call_active"):
                raise HealthError("UE call active; radio repair refused")
            if runtime.running(GATEWAY):
                channels = self.podman("exec", GATEWAY, "asterisk", "-rx",
                                       "core show channels count", label="Gateway idle guard")
                if not zero_channels(channels):
                    raise HealthError("Gateway not idle; radio repair refused")
            self.restore_ims = runtime.running(runtime.AGENT)
            self.progress("REPAIR one bounded idle UE/radio reconnect")
            runtime.stop()
            for name in ("open5gs-gnb", "ue-ue"):
                self.podman("restart", "--time", "5", name, label="Reconnect " + name, maximum=35)
        self.actions.append("one idle UE/radio reconnect")
        self.wait(lambda: self.internet() or self.not_ready("UE internet path"), 40, "UE internet")

    @staticmethod
    def not_ready(label):
        raise HealthError(label + " not ready")

    def diameter(self):
        for name in ("icscf", "scscf"):
            text = self.podman("exec", "dpt-ims-" + name, "kamcmd", "cdp.list_peers",
                               label=name.upper() + " Diameter")
            if not re.search(r"State:\s*[IR]_Open\b", text):
                raise HealthError(name.upper() + " HSS Diameter peer is not open")
        self.checks["diameter"] = True

    def ims(self):
        self.progress("CHECK HSS peers, IMS tunnel, protected registration and disarmed B2BUA")
        self.wait(self.diameter, 40 if self.repair else 1, "HSS Diameter peers")
        if self.repair:
            # Only known first-boot registration failure is eligible for one retry.
            for attempt in range(2):
                try:
                    start_cli.resume()
                    break
                except RuntimeError as error:
                    if attempt or not str(error).startswith("IMS registration agent stopped"):
                        raise
                    self.progress("REPAIR retry registration once after HSS readiness")
                    self.diameter()
            self.actions.append("resumed saved IMS/gateway services")
        checked = readiness(load_profile(runtime.PRIVATE / "sip-control-test/call-test.json"))
        if not checked["ready"]:
            raise HealthError("; ".join(checked["errors"]))
        self.checks["ims"] = {"ready": True, "ims_address": checked["ims_address"],
                              "gateway_disarmed": True}

    def dashboard_data(self):
        data = {}
        for endpoint in ("snapshot", "ims", "mdm", "gtp", "interfaces"):
            with urllib.request.urlopen(HTTP + "/api/" + endpoint,
                                        timeout=self.remaining(5)) as response:
                data[endpoint] = json.loads(response.read(2 * 1024 * 1024))
        now = time.time()
        snapshot = data["snapshot"]
        if snapshot.get("container_error") or now - (snapshot.get("container_updated") or 0) > 45:
            raise HealthError("Container monitoring is stale")
        for endpoint in ("ims", "interfaces"):
            if data[endpoint].get("stale") is not False:
                raise HealthError(endpoint + " monitoring is stale")
        mdm = data["mdm"]
        if not mdm.get("agent_fresh") or not mdm.get("native_fresh"):
            raise HealthError("UE MDM monitoring is stale")
        if data["gtp"].get("status") != "live":
            raise HealthError("GTP capture is not live")
        if data["ims"]["network_map"]["b2bua"].get("outbound_gate") != "disarmed":
            raise HealthError("Dashboard has not observed the disarmed gateway")
        for path in ("/", "/ims", "/mdm", "/gtp", "/interfaces", "/metrics"):
            with urllib.request.urlopen(HTTP + path, timeout=self.remaining(5)) as response:
                if response.status != 200:
                    raise HealthError("Monitoring page unavailable: " + path)
        return True

    def start_dashboard(self):
        script = str(ROOT / "monitoring/dashboard.py")
        matches = []
        for process in psutil.process_iter(["pid", "cmdline", "cwd"]):
            cmd = process.info["cmdline"] or []
            if (len(cmd) in (2, 4) and len(cmd) > 1
                    and cmd[1] in (script, "monitoring/dashboard.py")
                    and process.info["cwd"] == str(ROOT)
                    and (len(cmd) == 2 or cmd[2:] == ["--port", "8000"])):
                matches.append(process)
        if len(matches) > 1:
            raise HealthError("Multiple dashboard processes; refusing broad process cleanup")
        if matches:
            self.progress("REPAIR reload only the saved dashboard")
            matches[0].terminate()
            matches[0].wait(timeout=self.remaining(35))
        with socket.socket() as connection:
            if connection.connect_ex(("127.0.0.1", 8000)) == 0:
                raise HealthError("Port 8000 occupied by another process; refusing to replace it")
        folder = runtime.PRIVATE / "monitoring"
        folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (folder / "dashboard.log").open("ab") as log:
            process = subprocess.Popen([str(ROOT / ".venv/bin/python"), script], cwd=ROOT,
                                       stdout=log, stderr=log, start_new_session=True)
        (folder / "dashboard.pid").write_text(str(process.pid) + "\n")
        self.actions.append("started/reloaded saved dashboard")

    def monitoring(self):
        self.progress("CHECK dashboard pages and fresh MDM/IMS/GTP telemetry")
        try:
            self.dashboard_data()
        except (HealthError, OSError, ValueError):
            if not self.repair:
                raise HealthError("Monitoring unavailable/stale; read-only mode made no changes")
            self.start_dashboard()
            self.wait(self.dashboard_data, 55, "Monitoring")
        self.checks["monitoring"] = True

    def run(self):
        self.engine()
        if self.scope != "internet":
            baseline = start_cli.verify_module(restore_stopped=self.repair)
            if not baseline["verified"]:
                raise HealthError(baseline["reason"])
        self.containers()
        self.wait(self.core, 35 if self.repair else 1, "Core functions")
        if not self.internet():
            self.reconnect()
        if self.scope != "internet" or self.restore_ims:
            self.ims()
        if self.scope == "lab":
            self.monitoring()
        return {"ready": True, "scope": self.scope, "checks": self.checks,
                "actions": self.actions, "call_placed": False}


def main(scope="lab"):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true",
                        help="Observe/probe only; do not start, stop, repair or write reports")
    parser.add_argument("--json", action="store_true", help="Emit structured results; progress on stderr")
    parser.add_argument("--timeout", type=int, default=360, help="Overall deadline in seconds (30..600)")
    args = parser.parse_args()
    if not 30 <= args.timeout <= 600:
        parser.error("--timeout must be 30..600 seconds")
    runner = Runner(scope, not args.check_only, args.timeout, args.json)
    def expired(_signum, _frame):
        raise DeadlineExceeded("Overall recovery deadline reached")
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, args.timeout)
    try:
        if args.check_only:
            result = runner.run()
        else:
            os.umask(0o077)
            with lock(runtime.CLIENT / "lab-repair.lock"):
                result = runner.run()
        code = 0
    except KeyboardInterrupt:
        result = {"ready": False, "scope": scope, "error": "Interrupted; no further recovery attempted",
                  "checks": runner.checks, "actions": runner.actions, "call_placed": False}
        code = 130
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, yaml.YAMLError,
            subprocess.SubprocessError, psutil.Error) as error:
        result = {"ready": False, "scope": scope,
                  "error": str(error) if isinstance(error, HealthError) else type(error).__name__,
                  "checks": runner.checks, "actions": runner.actions, "call_placed": False}
        code = 2
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(("READY" if result["ready"] else "NOT READY") + " — " + scope)
        if result.get("error"):
            print(result["error"])
        print("No call placed. No destructive disk repair or credential changes.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
