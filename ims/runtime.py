"""Start/verify the existing lab and maintain IMS registration; never dial."""
import argparse
import copy
import datetime
import fcntl
import ipaddress
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

import yaml

from ims.lab import ROOT, settings
from ims.registration_state import agent_status, scscf_contact, sessions
from ims.ipsec_state import associations, peer_health

PRIVATE = Path.home() / ".config/dan-powell-technologies"
CLIENT = PRIVATE / "ims-client"
STATE = CLIENT / "registration-state"
AGENT = "dpt-ims-ue-client"
IMAGE = ("ghcr.io/lyatanski/pro2call@sha256:"
         "a5ec1f79392a0937b9c339df265b59e2cc13a0793b29e30b0b641d85026c11a8")
SERVICES = ("open5gs-mongodb", "dpt-ims-mysql", "dpt-ims-dns",
            "open5gs-nrf", "open5gs-scp", "open5gs-udr", "open5gs-udm",
            "open5gs-ausf", "open5gs-pcf", "open5gs-bsf", "open5gs-upf",
            "open5gs-smf", "open5gs-amf", "dpt-ims-pyhss", "dpt-ims-rtpengine",
            "dpt-ims-icscf", "dpt-ims-scscf", "dpt-ims-pcscf",
            "open5gs-gnb", "ue-ue", "ue-mdm")


def podman(*args, check=True, **kwargs):
    return subprocess.run(["podman", *args], capture_output=True,
                          check=check, timeout=kwargs.pop("timeout", 35), **kwargs)


def inspect(name):
    result = podman("inspect", name, check=False)
    return json.loads(result.stdout)[0] if result.returncode == 0 else None


def running(name):
    value = inspect(name)
    return bool(value and value["State"]["Status"] == "running")


def identity():
    value = yaml.safe_load((ROOT / "ims/subscriber.template.yaml").read_text())
    return str(value["imsi"]), str(value["msisdn"]).lstrip("+"), settings()["realm"]


def ue_sessions():
    imsi, _, _ = identity()
    result = podman("exec", "ue-ue", "nr-cli", "imsi-" + imsi, "-e", "ps-list",
                    check=False)
    return sessions(result.stdout.decode(errors="replace")) if result.returncode == 0 else {}


def select_ims_tunnel(current, interfaces, subnet):
    session = current.get("ims", {})
    if session.get("state") != "PS-ACTIVE":
        raise RuntimeError("An active IMS PDU session is required")
    address = ipaddress.IPv4Address(session.get("address", ""))
    if address not in ipaddress.IPv4Network(subnet):
        raise RuntimeError("IMS session address is outside the configured IMS subnet")
    if str(address) == current.get("internet", {}).get("address"):
        raise RuntimeError("IMS and internet session addresses must differ")
    matches = [
        row["ifname"] for row in interfaces
        if re.fullmatch(r"uesimtun\d+", row.get("ifname", ""))
        and "UP" in row.get("flags", [])
        and any(a.get("family") == "inet" and a.get("local") == str(address)
                for a in row.get("addr_info", []))
    ]
    if len(matches) != 1:
        raise RuntimeError("IMS session must map to exactly one active UERANSIM tunnel")
    return {"interface": matches[0], "address": str(address)}


def bind_agent(binding):
    """Publish an exact DNN binding; never rebind an active call."""
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = STATE / "tunnel-binding"
    if path.is_symlink():
        raise RuntimeError("Refusing a symlinked IMS tunnel binding")
    expected = binding["interface"] + "\n" + binding["address"] + "\n"
    fd = os.open(CLIENT / "call-cli.lock", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("UE call command active; IMS tunnel rebind refused")
        data = inspect(AGENT)
        active = bool(data and data["State"]["Status"] == "running")
        try:
            state = json.loads((STATE / "status.json").read_text())
        except (OSError, ValueError):
            state = {}
        same = (path.exists() and path.read_text() == expected
                and state.get("interface") == binding["interface"]
                and state.get("address") == binding["address"])
        if same:
            return
        if active:
            if state.get("call_active"):
                raise RuntimeError("IMS call active; tunnel rebind refused")
            if running("dpt-sip-control-test"):
                channels = podman("exec", "dpt-sip-control-test", "asterisk", "-rx",
                                  "core show channels count")
                if not re.search(rb"^\s*0 active channels\s*$", channels.stdout, re.M):
                    raise RuntimeError("Gateway not idle; IMS tunnel rebind refused")
            stop()
        temporary_fd, temporary = tempfile.mkstemp(prefix=".tunnel-binding-", dir=STATE)
        try:
            with os.fdopen(temporary_fd, "w") as output:
                output.write(expected)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    finally:
        os.close(fd)


def status():
    _, msisdn, realm = identity()
    impu = "sip:" + msisdn + "@" + realm
    observed = {"queried": False, "registered": None, "contacts": []}
    if running("dpt-ims-scscf"):
        result = podman("exec", "dpt-ims-scscf", "kamcmd", "ulscscf.showimpu", impu,
                        check=False)
        if result.returncode == 0:
            observed = scscf_contact(result.stdout.decode(errors="replace"), impu)
    vm_now = None
    if running(AGENT):
        clock = podman("exec", AGENT, "date", "+%s", check=False)
        if clock.returncode == 0 and clock.stdout.strip().isdigit():
            vm_now = int(clock.stdout.strip())
    agent = (agent_status(STATE / "status.json", now=vm_now) if vm_now is not None
             else {"state": "clock-unavailable", "registration_observed": False})
    current = ue_sessions() if running("ue-ue") else {}
    address = current.get("ims", {}).get("address")
    contact_matches = any(
        address and ("sip:" + address + ":") in row["uri"] and row["expires_in"] > 0
        for row in observed["contacts"])
    ipsec = {"verified": False, "missing": [], "scope": "IPsec state unavailable"}
    if (agent.get("registration_observed") and agent.get("address") == address
            and running("ue-ue") and running("dpt-ims-pcscf")):
        ue_state = podman("exec", "ue-ue", "ip", "xfrm", "state", "list", "nokeys",
                          check=False, timeout=8)
        peer_state = podman("exec", "dpt-ims-pcscf", "ip", "xfrm", "state", "list", "nokeys",
                            check=False, timeout=8)
        if ue_state.returncode == 0 and peer_state.returncode == 0:
            ipsec = peer_health(
                agent, settings()["services"]["pcscf"]["address"],
                associations(ue_state.stdout.decode()),
                associations(peer_state.stdout.decode()))
    verified = (running(AGENT) and agent.get("registration_observed", False)
                and agent.get("address") == address
                and observed["registered"] is True and contact_matches
                and current.get("ims", {}).get("state") == "PS-ACTIVE" and ipsec["verified"])
    return {"msisdn": "+" + msisdn, "realm": realm, "verified": verified,
            "sessions": current, "agent": agent, "scscf": observed, "ipsec": ipsec,
            "contact_matches_ims_address": contact_matches,
            "vm_clock_offset_seconds": round(vm_now - time.time(), 1) if vm_now else None,
            "scope": "Registration only; not an IMS call, audio or voice-QoS result."}


def stop():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    if running(AGENT):
        (STATE / "stop").touch(mode=0o600)
        for _ in range(25):
            if not running(AGENT):
                break
            if agent_status(STATE / "status.json").get("state") == "stopped":
                time.sleep(2)
                break
            time.sleep(.25)
        podman("stop", "--time", "5", AGENT)


def persist_sessions():
    """Update only session requests in the existing private ConfigMap volume."""
    data = inspect("ue-ue")
    mount = next(m for m in data["Mounts"] if m["Destination"] == "/etc/ueransim")
    if mount["Type"] != "volume" or mount.get("Name") != "ue-config":
        raise RuntimeError("Unexpected UE configuration mount; refusing speculative changes")
    original = podman("exec", "ue-ue", "cat", "/etc/ueransim/ue.yaml").stdout
    value = yaml.safe_load(original)
    existing = value.setdefault("sessions", [])
    if any(row.get("apn") == "ims" for row in existing):
        return False
    base = next((row for row in existing if row.get("apn") == "internet"), None)
    if base is None:
        raise RuntimeError("Internet session template missing")
    ims = copy.deepcopy(base)
    ims["apn"] = "ims"
    existing.append(ims)
    rendered = yaml.safe_dump(value, sort_keys=False).encode()
    before, after = yaml.safe_load(original), yaml.safe_load(rendered)
    before.pop("sessions", None)
    after.pop("sessions", None)
    if before != after:
        raise RuntimeError("Refusing to alter UE identities or authentication")
    backup = CLIENT / "backups" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup.mkdir(parents=True, mode=0o700)
    (backup / "ue.yaml").write_bytes(original)
    podman("run", "--rm", "-i", "--security-opt", "label=disable", "--volume", "ue-config:/cfg",
           "--entrypoint", "python3", "docker.io/library/python:3.12-slim", "-c",
           "import os,sys; p='/cfg/ue.yaml'; f=open(p,'wb'); "
           "f.write(sys.stdin.buffer.read()); f.close(); os.chmod(p,0o600)",
           input=rendered)
    return True


def install_agent():
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = inspect(AGENT)
    if data and (data["Config"].get("Labels") or {}).get("dpt.role") == "ims-registration":
        return
    env = CLIENT / "registration.env"
    if not env.exists():
        if not data:
            raise RuntimeError("Existing protected subscriber environment required")
        value = podman("exec", AGENT, "cat", "/run/ims-client.env").stdout.decode()
        _, msisdn, _ = identity()
        value += ("\nexport IMS_MSISDN=" + shlex.quote(msisdn)
                  + "\nexport IMS_VERBOSE=0\nexport IMS_DUMP=0\nexport IMS_IPSEC=1"
                  + "\nexport IMS_EXPIRES=600\nexport IMS_RENEW_SECONDS=240\n")
        env.write_text(value)
        env.chmod(0o600)
    if data:
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ").lower()
        (CLIENT / ("client-before-" + stamp + ".json")).write_text(json.dumps(data, indent=2))
        podman("stop", "--time", "5", AGENT)
        podman("update", "--restart", "no", AGENT)
        podman("rename", AGENT, AGENT + "-before-registration-" + stamp)
    podman("create", "--name", AGENT, "--pod", "ue", "--cap-add", "NET_ADMIN",
           "--security-opt", "label=disable", "--memory", "256m", "--cpus", "0.5",
           "--pids-limit", "64", "--restart", "on-failure:5", "--label",
           "dpt.role=ims-registration", "--volume", str(env) + ":/run/client.env:ro",
           "--volume", str(STATE) + ":/run/dpt-registration:rw",
           "--volume", str(ROOT / "ims/registration_agent.lua") + ":/opt/dpt_registration.lua:ro",
           "--volume", str(ROOT / "ims/call_control.lua") + ":/opt/dpt_call_control.lua:ro",
           "--entrypoint", "sh", IMAGE, "-c",
           "umask 077; . /run/client.env; exec lua /opt/dpt_registration.lua")


def up(repair_ue=False):
    os.umask(0o077)
    CLIENT.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name in SERVICES:
        if not inspect(name):
            raise RuntimeError("Saved lab container missing: " + name)
        if not running(name):
            podman("start", name)
    changed = persist_sessions()
    if repair_ue:
        if running("dpt-sip-control-test"):
            result = podman("exec", "dpt-sip-control-test", "asterisk", "-rx",
                            "core show channels count", check=False)
            if result.returncode or not re.search(rb"^\s*0 active channels\s*$", result.stdout, re.M):
                raise RuntimeError("Active gateway channels; UE recovery refused")
        if inspect(AGENT) and (STATE / "status.json").exists():
            stop()
        podman("restart", "--time", "5", "open5gs-gnb")
        podman("restart", "--time", "5", "ue-ue")
    imsi, _, _ = identity()
    for _ in range(60):
        current = ue_sessions()
        if current.get("internet", {}).get("state") == "PS-ACTIVE":
            break
        time.sleep(.5)
    else:
        raise RuntimeError("5G Internet PDU session did not become active")
    if "ims" not in current:
        podman("exec", "ue-ue", "nr-cli", "imsi-" + imsi, "-e",
               "ps-establish IPv4 --dnn ims --sst 1")
    for _ in range(60):
        current = ue_sessions()
        if current.get("ims", {}).get("state") == "PS-ACTIVE":
            break
        time.sleep(.5)
    else:
        raise RuntimeError("IMS PDU session did not become active")
    # Do not treat attached-but-stale radio state as a working data path.
    address = current["internet"]["address"]
    probe = ("import socket; s=socket.create_connection(('1.1.1.1',443),"
             "timeout=5,source_address=(" + repr(address) + ",0)); s.close()")
    if podman("exec", "ue-mdm", "python3", "-c", probe, check=False).returncode:
        raise RuntimeError("UE Internet path failed; use up --repair-ue for a bounded radio reconnect")
    install_agent()
    interfaces = json.loads(podman("exec", "ue-ue", "ip", "-j", "-4", "address", "show",
                                   timeout=8).stdout)
    bind_agent(select_ims_tunnel(current, interfaces, settings()["network"]["ims_ue_subnet"]))
    for marker in ("stop", "renew-now"):
        (STATE / marker).unlink(missing_ok=True)
    if not running(AGENT):
        podman("start", AGENT)
    recovery_requested = False
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        result = status()
        if result["verified"]:
            result["ue_session_requests_persisted"] = changed
            return result
        if not running(AGENT):
            raise RuntimeError("IMS registration agent stopped; state: "
                               + str(result["agent"].get("state", "unknown")))
        if (not recovery_requested and result["agent"].get("registration_observed")
                and not result["ipsec"]["verified"]):
            (STATE / "renew-now").touch(mode=0o600)
            recovery_requested = True
        time.sleep(.5)
    raise RuntimeError("Registration did not verify; inspect runtime status, not a green container")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("up", "status", "stop", "renew"))
    parser.add_argument("--repair-ue", action="store_true")
    args = parser.parse_args()
    if args.action == "up":
        print(json.dumps(up(args.repair_ue), indent=2))
    elif args.action == "status":
        print(json.dumps(status(), indent=2))
    elif args.action == "stop":
        stop()
        print(json.dumps(status(), indent=2))
    else:
        if not running(AGENT):
            raise RuntimeError("Registration agent is not running")
        (STATE / "renew-now").touch(mode=0o600)
        print("Authenticated registration renewal requested; no call requested.")


if __name__ == "__main__":
    main()
