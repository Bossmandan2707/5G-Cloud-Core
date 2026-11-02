"""Read-only network metadata; no subscriber keys or packet payloads are exposed."""
import copy
import ipaddress
import json
import platform
import re
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

import psutil
import yaml


ROOT = Path(__file__).resolve().parent.parent
NFS = ("nrf", "amf", "smf", "upf", "ausf", "udm", "udr", "pcf")
SERVICES = {"sbi": ("tcp", 7777), "ngap": ("sctp", 38412),
            "pfcp": ("udp", 8805), "gtpu": ("udp", 2152),
            "gtpc": ("udp", 2123), "metrics": ("tcp", 9090)}
READ_NETWORK = r"""
printf '__ADDR__\n'; ip -j addr
printf '__ROUTES__\n'; ip -j route
printf '__SOCKETS__\n'; ss -H -lntu 2>/dev/null || printf 'unavailable\n'
printf '__EPS__\n'; cat /proc/net/sctp/eps 2>/dev/null
printf '__ASSOCS__\n'; cat /proc/net/sctp/assocs 2>/dev/null
printf '__FORWARD__\n'; cat /proc/sys/net/ipv4/ip_forward 2>/dev/null
printf '__NAT__\n'; iptables -t nat -S POSTROUTING 2>/dev/null || true
"""


def load_layout(path=ROOT / "open5gs-pod.yaml"):
    docs = list(yaml.safe_load_all(Path(path).read_text()))
    data = next((d["data"] for d in docs if isinstance(d, dict) and d.get("kind") == "ConfigMap"
                 and d.get("metadata", {}).get("name") == "open5gs-config"), None)
    if data is None:
        raise ValueError("Missing core ConfigMap")
    configs = {name: yaml.safe_load(data[name + ".yaml"]) for name in NFS}
    endpoints = []
    for name, document in configs.items():
        for service, (protocol, default) in SERVICES.items():
            for index, server in enumerate(document[name].get(service, {}).get("server", [])):
                endpoints.append({"id": f"{name}-{service}-{index}", "component": name.upper(),
                                  "service": service, "address": str(server["address"]),
                                  "port": int(server.get("port", default)), "protocol": protocol,
                                  "container": "open5gs-" + name, "source": "manifest"})
    gnb = yaml.safe_load(data["gnb.yaml"])
    endpoints.append({"id": "gnb-gtpu-0", "component": "gNB", "service": "gtpu",
                      "address": gnb["gtpIp"], "port": 2152, "protocol": "udp",
                      "container": "open5gs-gnb", "source": "manifest"})
    # The deployment rewrites linkIp to the core eth0 address at startup.
    endpoints.append({"id": "gnb-radio-0", "component": "gNB", "service": "radio",
                      "address": None, "port": 4997, "protocol": "udp",
                      "container": "open5gs-gnb", "source": "runtime address required"})
    uri = urlparse(configs["udr"]["db_uri"])
    endpoints.append({"id": "mongodb-db-0", "component": "MongoDB", "service": "database",
                      "address": uri.hostname, "port": uri.port or 27017, "protocol": "tcp",
                      "container": "open5gs-mongodb", "source": "manifest"})
    return endpoints


def parse_sockets(text):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0] not in ("tcp", "udp"):
            continue
        address, _, port = fields[4].rpartition(":")
        if port.isdigit():
            rows.append({"protocol": fields[0], "state": fields[1],
                         "address": address.strip("[]"), "port": int(port)})
    return rows


def parse_sctp(text, associations=False):
    rows = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        try:
            if associations:
                arrow = fields.index("<->")
                rows.append({"state": int(fields[4]), "local_port": int(fields[11]),
                             "remote_port": int(fields[12]), "local": fields[13].lstrip("*"),
                             "remote": fields[arrow + 1].lstrip("*")})
            else:
                rows.append({"address": fields[8], "port": int(fields[5])})
        except (ValueError, IndexError):
            continue
    return rows


def parse_namespace(text):
    blocks = {}
    key = None
    for line in text.splitlines():
        if re.fullmatch(r"__[A-Z]+__", line):
            key = line
            blocks[key] = []
        elif key:
            blocks[key].append(line)
    def block(name):
        return "\n".join(blocks.get("__" + name + "__", []))
    devices = []
    for row in json.loads(block("ADDR")):
        devices.append({"name": row["ifname"], "admin_up": "UP" in row.get("flags", []),
                        "kernel_state": row.get("operstate", "UNKNOWN"),
                        "addresses": [a["local"] + "/" + str(a["prefixlen"])
                                      for a in row.get("addr_info", [])
                                      if a.get("family") in ("inet", "inet6")]})
    return {"devices": devices, "routes": json.loads(block("ROUTES")),
            "sockets": parse_sockets(block("SOCKETS")),
            "sockets_available": block("SOCKETS").strip() != "unavailable",
            "sctp": parse_sctp(block("EPS")),
            "associations": parse_sctp(block("ASSOCS"), True),
            "forwarding": block("FORWARD").strip() == "1",
            "nat_sources": [match.group(1) for line in block("NAT").splitlines()
                            if "MASQUERADE" in line
                            for match in [re.search(r"(?:^|\s)-s\s+(\S+)", line)] if match],
            "error": None, "updated": time.time()}


def unknown_namespace(message):
    return {"devices": [], "routes": [], "sockets": [], "sctp": [], "associations": [],
            "sockets_available": False, "forwarding": False, "nat_sources": [],
            "error": message, "updated": None}


def device(ns, name):
    return next((d for d in ns["devices"] if d["name"] == name), None)


def device_address(row):
    if not row:
        return None
    return next((a for a in row["addresses"] if ":" not in a), None)


def default_route(ns):
    return next((r for r in ns["routes"] if r.get("dst") in ("default", "0.0.0.0/0")), {})


def observe_endpoint(endpoint, core, states):
    row = dict(endpoint)
    if row["service"] == "radio":
        binding = next((s for s in core["sockets"]
                        if s["protocol"] == "udp" and s["port"] == 4997), None)
        row["address"] = binding["address"] if binding else device_address(device(core, "eth0"))
        if row["address"] and "/" in row["address"]:
            row["address"] = row["address"].split("/")[0]
        row["source"] = "live socket" if binding else "live core eth0"
    row["status"] = "unknown"
    state = states.get(row["container"])
    if state and state != "running":
        row["status"] = "down"
    elif not core["error"]:
        if row["protocol"] == "sctp":
            matched = any(s["address"] == row["address"] and s["port"] == row["port"]
                          for s in core["sctp"])
            row["status"] = "listening" if matched else "not observed"
        elif core["sockets_available"]:
            matched = any(s["protocol"] == row["protocol"] and s["port"] == row["port"]
                          and s["address"] in (row["address"], "0.0.0.0")
                          and (s["state"] == "LISTEN" or row["protocol"] == "udp")
                          for s in core["sockets"])
            row["status"] = ("listening" if row["protocol"] == "tcp" else "bound") if matched else "not observed"
    return row


def build_map(layout, namespaces, states, now=None):
    now = time.time() if now is None else now
    core, ue = namespaces["core"], namespaces["ue"]
    endpoints = [observe_endpoint(e, core, states) for e in layout]
    def endpoint(nf, service):
        return next((e for e in endpoints if e["component"].lower() == nf
                     and e["service"] == service),
                    {"component": nf.upper(), "address": None, "port": None,
                     "status": "unknown", "protocol": ""})
    def end(label, address, port=None):
        return {"component": label, "address": address, "port": port}
    links = []
    def link(name, left, right, status, note, group="core"):
        links.append({"name": name, "left": left, "right": right,
                      "status": status, "note": note, "group": group})
    def pair_status(a, b):
        if "down" in (a["status"], b["status"]):
            return "down"
        if all(e["status"] in ("bound", "listening") for e in (a, b)):
            return "endpoints observed"
        return "unknown"
    gnb, upf = endpoint("gnb", "gtpu"), endpoint("upf", "gtpu")
    amf = endpoint("amf", "ngap")
    ue_ip = device_address(device(ue, "eth0"))
    core_ip = device_address(device(core, "eth0"))
    tunnel = device(ue, "uesimtun0")
    ogstun = device(core, "ogstun")
    radio = endpoint("gnb", "radio")
    link("N1", end("UE (logical NAS)", ue_ip), end("AMF (logical NAS)", amf["address"]), "logical",
         "N1 is UE–AMF NAS signaling through radio/N2. IPs are hosting context; N1 has no separate TCP/UDP port.")
    association = next((a for a in core["associations"] if a["state"] == 3
                        and a["remote"] == amf["address"] and a["remote_port"] == amf["port"]
                        and a["local"] == gnb["address"]), None)
    n2_status = "established" if association else ("listening" if amf["status"] == "listening" else amf["status"])
    if any(states.get(c) not in (None, "running") for c in ("open5gs-amf", "open5gs-gnb")):
        n2_status = "down"
    link("N2", end("gNB", association["local"] if association else gnb["address"],
                   association["local_port"] if association else None), amf, n2_status,
         "NGAP / SCTP. Established is based on a current kernel SCTP association.")
    link("N3", gnb, upf, pair_status(gnb, upf),
         "GTP-U / UDP 2152. Bound sockets are not proof of traffic; see the GTP traces tab.")
    smf_pfcp, upf_pfcp = endpoint("smf", "pfcp"), endpoint("upf", "pfcp")
    link("N4", smf_pfcp, upf_pfcp, pair_status(smf_pfcp, upf_pfcp),
         "PFCP / UDP 8805. This is socket state, not a decoded PFCP association.")
    route = default_route(core)
    tunnel_subnet = str(ipaddress.ip_interface(device_address(ogstun)).network) if device_address(ogstun) else None
    routing = bool(ogstun and ogstun["admin_up"] and device(core, "eth0")
                   and device(core, "eth0")["admin_up"] and core["forwarding"]
                   and tunnel_subnet in core["nat_sources"] and route)
    link("N6", end("UPF / core eth0", core_ip), end("Data-network next hop", route.get("gateway")),
         "routing ready" if routing else "unknown",
         "UPF ogstun " + str(device_address(ogstun) or "not observed") +
         " forwards/NATs through the core uplink to this gateway; internet reachability is not actively probed.", "path")
    link("Radio simulation", end("UE eth0", ue_ip), radio,
         "endpoint observed" if ue_ip and radio["status"] == "bound" else "unknown",
         "UERANSIM simulated radio over UDP 4997. UE source port is not correlated.", "path")
    link("UE tunnel", end("UE uesimtun0", device_address(tunnel)), end("UPF ogstun", device_address(ogstun)),
         "interfaces up" if tunnel and ogstun and tunnel["admin_up"] and ogstun["admin_up"] else "unknown",
         "Logical PDU data path via gNB/N3. Kernel UNKNOWN is normal for an administratively UP TUN device.", "path")
    for name, a, b in (("N7", "smf", "pcf"), ("N8", "amf", "udm"),
                       ("N10", "smf", "udm"), ("N11", "amf", "smf"),
                       ("N12", "amf", "ausf"), ("N13", "ausf", "udm"),
                       ("N15", "amf", "pcf"), ("N35", "udm", "udr")):
        left, right = endpoint(a, "sbi"), endpoint(b, "sbi")
        link(name, left, right, pair_status(left, right),
             "Logical service-based reference point. Addresses are server SBI endpoints, not correlated client sockets or proof of a service transaction.", "sbi")
    for nf in ("amf", "smf", "ausf", "udm", "udr", "pcf"):
        left, right = endpoint(nf, "sbi"), endpoint("nrf", "sbi")
        link("Nnrf · " + nf.upper(), left, right, pair_status(left, right),
             "NRF registration/discovery service endpoints; transactions are not inspected.", "sbi")
    db = endpoint("mongodb", "database")
    for nf in ("UDR", "PCF"):
        link(nf + " database", end(nf + " DB client", None), db,
             "listener observed" if db["status"] == "listening" else db["status"],
             "MongoDB TCP 27017. The application's ephemeral client-source IP/port is not attributed.", "database")
    for scope, label in (("vm", "Podman VM"), ("host", "Mac host")):
        ns = namespaces[scope]
        r = default_route(ns)
        uplink = device(ns, r.get("dev"))
        link(label + " uplink", end((uplink or {}).get("name", label), device_address(uplink)),
             end("Default gateway", r.get("gateway")),
             "route observed" if r and uplink and uplink["admin_up"] else "unknown",
             "Current default-route metadata; not an end-to-end reachability probe.", "path")
    nodes = []
    for name in ("UE", "gNB", "AMF", "SMF", "UPF", "NRF", "AUSF", "UDM", "UDR", "PCF", "MongoDB", "DN"):
        related = [e for e in endpoints if e["component"] == name]
        address = next((e["address"] for e in related if e["address"]), None)
        status = "unknown"
        if related:
            status = "observed" if any(e["status"] in ("bound", "listening") for e in related) else related[0]["status"]
        if name == "UE":
            address = device_address(tunnel) or ue_ip
            status = "interface up" if tunnel and tunnel["admin_up"] else "unknown"
        if name == "DN":
            address, status = route.get("gateway"), "not probed"
        nodes.append({"name": name, "address": address, "status": status})
    public = {scope: {key: ns.get(key) for key in ("devices", "routes", "error", "updated")}
              for scope, ns in namespaces.items()}
    return {"updated": now, "stale": False, "nodes": nodes, "links": links,
            "endpoints": endpoints, "namespaces": public,
            "errors": [scope + ": " + ns["error"] for scope, ns in namespaces.items() if ns["error"]],
            "not_deployed": ["N5 / AF", "N9 / second UPF", "N14 / second AMF",
                             "N16 / second SMF", "N22 / NSSF", "N36 / PCF–UDR service"]}


def collect_host():
    addresses = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    devices = [{"name": name, "admin_up": bool(stats.get(name) and stats[name].isup),
                "kernel_state": "UP" if stats.get(name) and stats[name].isup else "DOWN",
                "addresses": [a.address for a in rows if a.family in (socket.AF_INET, socket.AF_INET6)]}
               for name, rows in addresses.items()]
    routes = []
    if platform.system() == "Darwin":
        result = subprocess.run(["/sbin/route", "-n", "get", "default"],
                                capture_output=True, text=True, timeout=4, check=True)
        fields = dict(re.findall(r"^\s*(gateway|interface):\s*(\S+)", result.stdout, re.MULTILINE))
        if "gateway" in fields and "interface" in fields:
            routes.append({"dst": "default", "gateway": fields["gateway"], "dev": fields["interface"]})
    return {"devices": devices, "routes": routes, "error": None, "updated": time.time()}


class InterfaceMonitor:
    def __init__(self, podman):
        self.podman = podman
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.thread = None
        self.data = {"updated": None, "stale": True, "nodes": [], "links": [], "endpoints": [],
                     "namespaces": {}, "errors": ["Waiting for live interface samples."], "not_deployed": []}

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def namespace(self, scope):
        try:
            if not self.podman:
                raise OSError("Podman unavailable")
            prefix = [self.podman, "machine", "ssh"] if scope == "vm" else [
                self.podman, "exec", "open5gs-upf" if scope == "core" else "ue-ue", "sh", "-c"]
            result = subprocess.run(prefix + [READ_NETWORK], capture_output=True, text=True,
                                    timeout=10, check=True)
            return parse_namespace(result.stdout)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            return unknown_namespace("Live namespace unavailable (VM/container may be stopped).")

    def run(self):
        while not self.stop.is_set():
            try:
                layout = load_layout()
                with ThreadPoolExecutor(max_workers=3) as pool:
                    futures = {scope: pool.submit(self.namespace, scope) for scope in ("core", "ue", "vm")}
                    try:
                        host = collect_host()
                    except (OSError, subprocess.SubprocessError):
                        host = unknown_namespace("Host default-route information unavailable.")
                    namespaces = {scope: future.result() for scope, future in futures.items()}
                    namespaces["host"] = host
                states = {}
                try:
                    result = subprocess.run([self.podman, "ps", "-a", "--format", "{{.Names}}\t{{.State}}"],
                                            capture_output=True, text=True, timeout=5, check=True)
                    states = dict(line.split("\t", 1) for line in result.stdout.splitlines() if "\t" in line)
                except (OSError, TypeError, subprocess.SubprocessError):
                    pass
                data = build_map(layout, namespaces, states)
                with self.lock:
                    self.data = data
            except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError):
                with self.lock:
                    self.data = {"updated": None, "stale": True, "nodes": [], "links": [], "endpoints": [],
                                 "namespaces": {}, "errors": ["Interface configuration or observation could not be read."],
                                 "not_deployed": []}
            self.stop.wait(15)

    def snapshot(self, now=None):
        with self.lock:
            data = copy.deepcopy(self.data)
        now = time.time() if now is None else now
        data["stale"] = data["updated"] is None or now - data["updated"] > 45
        if data["stale"]:
            for row in data["nodes"] + data["links"] + data["endpoints"]:
                row["status"] = "stale"
        return data

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=20)
