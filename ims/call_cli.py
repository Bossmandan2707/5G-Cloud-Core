"""One bounded UE-originated test call; no AI discovery or configuration edits."""
import argparse
import datetime
import fcntl
import json
import os
import re
import secrets
import signal
import subprocess
import time
from pathlib import Path

from ims.call_prep import load_profile
from ims.runtime import PRIVATE, STATE, status, inspect
from ims.sip_trace import extract, messages, render
from ims.trace_call import collect, start

GATEWAY = "dpt-sip-control-test"


def cli(command, check=True):
    return subprocess.run(["podman", "exec", GATEWAY, "asterisk", "-rx", command],
                          capture_output=True, text=True, check=check, timeout=10).stdout


def gateway_log():
    return subprocess.run(["podman", "exec", GATEWAY, "cat", "/var/log/asterisk/messages"],
                          capture_output=True, check=True, timeout=10).stdout

def zero_channels(text):
    return bool(re.search(r"^\s*0 active channels\s*$", text, re.M))


def gateway_expiring(data):
    if "sleep 1800" not in " ".join(data["Config"].get("Cmd") or []):
        return False
    started = datetime.datetime.fromisoformat(
        re.sub(r"(\.\d{6})\d+", r"\1", data["State"]["StartedAt"]).replace("Z", "+00:00"))
    clock = subprocess.run(["podman", "exec", GATEWAY, "date", "+%s"],
                           capture_output=True, text=True, check=True, timeout=10)
    return int(clock.stdout.strip()) - started.timestamp() > 1500


def ensure_gateway():
    data = inspect(GATEWAY)
    if not data:
        raise RuntimeError("Saved B2BUA container missing; refusing to recreate it")
    if data["State"]["Status"] == "running":
        if gateway_expiring(data):
            if not zero_channels(cli("core show channels count", False)):
                raise RuntimeError("Temporary gateway needs refresh but is not confirmed idle")
            cli("dialplan set global DPT_OUTBOUND_ARMED 0")
            subprocess.run(["podman", "restart", "--time", "5", GATEWAY],
                           capture_output=True, check=True, timeout=30)
    if data["State"]["Status"] != "running":
        subprocess.run(["podman", "start", GATEWAY], capture_output=True, check=True, timeout=30)
    if "active channels" not in cli("core show channels count", False):
        subprocess.run(["podman", "exec", "-d", GATEWAY, "sh", "-c",
                        "umask 077; exec asterisk -f -g -vvv"],
                       capture_output=True, check=True, timeout=10)
    for _ in range(30):
        output = cli("core show channels count", False)
        if "active channels" in output:
            return
        time.sleep(.5)
    raise RuntimeError("Saved B2BUA did not become ready")


def readiness(profile):
    from ims.start_cli import verify_module
    registration = status()
    errors = []
    if not registration["verified"]:
        errors.append("UE/S-CSCF registration or peer SPI check is not verified")
    module = verify_module()
    if not module["verified"]:
        errors.append(module["reason"])
    pcscf = subprocess.run(["podman", "exec", "dpt-ims-pcscf", "kamcmd", "ulpcscf.status"],
                           capture_output=True, text=True, timeout=10)
    if pcscf.returncode or "State: registered" not in pcscf.stdout:
        errors.append("P-CSCF contact is not registered")
    try:
        gateway = inspect(GATEWAY)
        if not gateway or gateway["State"]["Status"] != "running":
            errors.append("B2BUA container stopped; run network-start")
        elif gateway_expiring(gateway):
            errors.append("Temporary gateway needs an idle refresh; run network-start")
        if not zero_channels(cli("core show channels count")):
            errors.append("Dedicated test B2BUA is busy")
        if not re.search(r"^\s*DPT_OUTBOUND_ARMED=0\s*$", cli("dialplan show globals"), re.M):
            errors.append("Gateway is not confirmed disarmed")
        endpoint = cli("pjsip show endpoint telnyx")
        for key, value in (("from_user", profile["external_caller_id"]),
                           ("contact_user", profile.get("connection_username", ""))):
            if not value or not re.search(r"^\s*" + key + r"\s*:\s*" + re.escape(value)
                                          + r"\s*$", endpoint, re.M):
                errors.append("Loaded Telnyx " + key + " does not match private profile")
        if not re.search(r"^\s*send_pai\s*:\s*(true|yes)\s*$", endpoint, re.M):
            errors.append("Telnyx P-Asserted-Identity is not enabled")
    except (OSError, subprocess.SubprocessError):
        errors.append("B2BUA unavailable; run network-start first")
    return {"ready": not errors, "errors": errors, "msisdn": registration["msisdn"],
            "ims_address": registration["agent"].get("address"),
            "destination": profile["destination"],
            "external_caller_id": profile["external_caller_id"]}


def last_result():
    folder = Path((PRIVATE / "ims-client/latest-end-to-end-path").read_text().strip()).resolve()
    if folder.parent != (PRIVATE / "traces").resolve():
        raise ValueError("Unexpected saved trace location")
    return folder, json.loads((folder / "end-to-end-result.json").read_text())


def show_trace(folder, report, point="ue"):
    path = folder / "sip-trace.json"
    trace = json.loads(path.read_text()) if path.exists() else extract(
        folder, (report.get("ue_call") or {}).get("call_id"))
    print("\nSIP TRACE — saved sanitized headers; authentication omitted")
    print(render(trace, None if point == "all" else point))
    invite = next((e for e in trace["events"] if e["point"] == "ue"
                   and e["start_line"].startswith("INVITE ")), None)
    if invite:
        print("\nUE INITIAL INVITE\n" + invite["message"])
    print("\nTrace folder: " + str(folder))


def call(profile, preflight=False):
    os.umask(0o077)
    lockpath = PRIVATE / "ims-client/call-cli.lock"
    fd = os.open(lockpath, os.O_WRONLY | os.O_CREAT, 0o600)
    folder = None
    locked = logger = False
    request = secrets.token_hex(16)
    report = {"test": "UE -> IMS -> B2BUA -> Telnyx", "preflight": preflight,
              "destination": profile["destination"],
              "external_caller_id": profile["external_caller_id"],
              "request_id": request, "audio_verified": False, "fallback_used": False,
              "created_at_host": time.time(), "passed": False}
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        checked = readiness(profile)
        if not checked["ready"]:
            raise RuntimeError("; ".join(checked["errors"]))
        logger = True
        cli("pjsip set logger on")
        offset = len(gateway_log())
        folder = start(90)
        if not preflight:
            cli("dialplan set global DPT_CALL_ARM_TOKEN " + request)
            cli("dialplan set global DPT_OUTBOUND_ARMED 1")
            if not re.search(r"^\s*DPT_OUTBOUND_ARMED=1\s*$",
                             cli("dialplan show globals"), re.M):
                raise RuntimeError("Gateway arming not confirmed")
            watchdog = ('sleep 45; current=$(asterisk -rx "dialplan show globals"); '
                        'case "$current" in *"DPT_CALL_ARM_TOKEN=$1"*) '
                        'asterisk -rx "dialplan set global DPT_OUTBOUND_ARMED 0" >/dev/null;; esac')
            subprocess.run(["podman", "exec", "-d", GATEWAY, "sh", "-c",
                            watchdog, "watchdog", request], capture_output=True, check=True, timeout=10)
        vm_now = int(subprocess.run(["podman", "exec", "dpt-ims-ue-client", "date", "+%s"],
                     capture_output=True, text=True, check=True, timeout=10).stdout.strip())
        pending = STATE / "call-request.tmp"
        pending.write_text(request + "\n" + profile["destination"] + "\n"
                           + str(vm_now + 30) + "\n")
        pending.replace(STATE / "call-request")
        deadline, last_event = time.monotonic() + 40, None
        while time.monotonic() < deadline:
            try:
                value = json.loads((STATE / "call-status.json").read_text())
            except (OSError, ValueError):
                value = {}
            if value.get("request_id") == request:
                report["ue_call"] = value
                if value.get("last_event") != last_event:
                    last_event = value.get("last_event")
                    if last_event:
                        print("UE: " + last_event, flush=True)
                if value.get("state") in ("done", "rejected"):
                    break
            time.sleep(.3)
        text = gateway_log()[offset:].decode(errors="replace")
        if not preflight and report.get("ue_call", {}).get("answered"):
            for _ in range(10):
                if "DPT_IMS_RESULT" in text:
                    break
                time.sleep(.1)
                text = gateway_log()[offset:].decode(errors="replace")
        report["gateway_dial_results"] = [
            {"status": a, "cause": b}
            for a, b in re.findall(r"DPT_IMS_RESULT status=([A-Z]*) cause=(\d+)", text)]
        report["gateway_local_gate_reached"] = "DPT_PREFLIGHT_BLOCKED" in text
        report["provider_dial_executed"] = bool(re.search(r"Executing.*Dial\(", text))
        ue = report.get("ue_call", {})
        report["passed"] = (
            bool(ue.get("answered") and ue.get("release_ok") and ue.get("final_status") == 200
                 and any(r["status"] == "ANSWER" and r["cause"] == "16"
                         for r in report["gateway_dial_results"]))
            if not preflight else bool(report["gateway_local_gate_reached"]
                                       and not report["provider_dial_executed"]))
        report["_safe_endpoint_events"] = messages(text.encode(), "b2bua-log", time.time())
    except BlockingIOError:
        raise RuntimeError("Another ue-call command is already running")
    finally:
        try:
            if locked and logger:
                if folder and report.get("ue_call", {}).get("state") not in ("done", "rejected"):
                    try:
                        (STATE / "call-stop").write_text(request)
                    except OSError:
                        pass
                for command in ("dialplan set global DPT_OUTBOUND_ARMED 0",
                                "dialplan set global DPT_CALL_ARM_TOKEN cleared"):
                    try:
                        cli(command)
                    except (OSError, subprocess.SubprocessError):
                        pass
                try:
                    if not zero_channels(cli("core show channels count")):
                        cli("channel request hangup all")
                    report["gateway_disarmed"] = bool(re.search(
                        r"^\s*DPT_OUTBOUND_ARMED=0\s*$", cli("dialplan show globals"), re.M))
                    report["active_gateway_channels_zero"] = zero_channels(cli("core show channels count"))
                except (OSError, subprocess.SubprocessError):
                    report["gateway_disarmed"] = False
            if folder:
                capture, count = collect(folder)
                report.update(capture=str(capture), packets=count)
                trace = extract(folder, (report.get("ue_call") or {}).get("call_id"))
                trace["events"].extend(report.pop("_safe_endpoint_events", []))
                (folder / "sip-trace.json").write_text(json.dumps(trace, indent=2))
                report["registration_preserved"] = status()["verified"]
                (folder / "end-to-end-result.json").write_text(json.dumps(report, indent=2))
                pointer = ("latest-preflight-cli-path" if preflight else "latest-end-to-end-path")
                (PRIVATE / "ims-client" / pointer).write_text(str(folder))
        finally:
            try:
                if logger:
                    cli("pjsip set logger off", False)
            except (OSError, subprocess.SubprocessError):
                pass
            finally:
                os.close(fd)
    return folder, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true", help="Readiness only; never dial")
    group.add_argument("--last-trace", action="store_true", help="Show saved UE trace; never dial")
    group.add_argument("--preflight", action="store_true", help="Local disarmed signaling test")
    parser.add_argument("--trace", action="store_true", help="Print sanitized SIP trace")
    parser.add_argument("--trace-point", choices=("ue", "pcscf", "scscf", "b2bua", "all"),
                        default="ue")
    parser.add_argument("--start", action="store_true", help="Resume saved lab before checking/calling")
    args = parser.parse_args()
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if args.last_trace:
            folder, report = last_result()
            show_trace(folder, report, args.trace_point)
            return 0
        profile = load_profile(PRIVATE / "sip-control-test/call-test.json")
        if args.start:
            from ims.start_cli import resume
            resume()
        if args.check:
            result = readiness(profile)
            print(json.dumps(result, indent=2))
            return 0 if result["ready"] else 2
        print("One " + ("DISARMED preflight" if args.preflight else "UE-originated call")
              + " to " + profile["destination"] + "; outbound caller " + profile["external_caller_id"],
              flush=True)
        folder, result = call(profile, args.preflight)
        print("Result: " + ("PASS" if result["passed"] else "NOT COMPLETED"))
        print("Gateway disarmed: " + str(result.get("gateway_disarmed", False)))
        if args.trace:
            show_trace(folder, result, args.trace_point)
        else:
            print("Saved trace: " + str(folder))
        return 0 if (result["passed"] and result.get("gateway_disarmed")
                     and result.get("active_gateway_channels_zero")
                     and result.get("registration_preserved")) else 1
    except KeyboardInterrupt:
        print("Interrupted; call cleanup/disarming was requested.")
        return 130
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("ue-call: " + str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
