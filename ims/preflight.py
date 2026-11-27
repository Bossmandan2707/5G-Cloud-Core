"""Validate a registered UE's IMS route against a disarmed local gateway."""
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path

from ims.call_prep import load_profile
from ims.trace_call import collect, start


PRIVATE = Path.home() / ".config/dan-powell-technologies"
ROOT = Path(__file__).resolve().parent.parent


def command(*args, **kwargs):
    return subprocess.run(["podman", *args], capture_output=True, check=True, **kwargs)


def provider_invites(text):
    outbound_tls, count = False, 0
    for line in text.splitlines():
        if "<---" in line:
            outbound_tls = "Transmitting SIP request" in line and "to TLS:" in line
        elif line.startswith("INVITE ") and outbound_tls:
            count += 1
    return count


def run():
    os.umask(0o077)
    profile = load_profile(PRIVATE / "sip-control-test/call-test.json")
    gate = command("exec", "dpt-sip-control-test", "asterisk", "-rx",
                   "dialplan show globals").stdout.decode()
    if not re.search(r"^\s*DPT_OUTBOUND_ARMED=0\s*$", gate, re.M):
        raise RuntimeError("Gateway must already be disarmed; runner cannot arm it")
    for source, destination in (("call_control.lua", "dpt_call_control.lua"),
                                ("ue_call.lua", "dpt_ue_call.lua")):
        command("cp", str(ROOT / "ims" / source),
                "dpt-ims-ue-client:/opt/" + destination)
    command("exec", "dpt-sip-control-test", "asterisk", "-rx", "pjsip set logger on")

    def log():
        return command("exec", "dpt-sip-control-test", "cat",
                       "/var/log/asterisk/messages").stdout

    before = len(log())
    folder = None
    report = {"mode": "disarmed_local_preflight", "gateway_block_verified": False,
              "provider_dial_executed": False, "provider_invites": 0, "passed": False}
    try:
        folder = start(90)
        time.sleep(1)
        session = json.loads((folder / "session.json").read_text())
        for point in session["points"]:
            running = command("inspect", "--format", "{{.State.Running}}",
                              point["container"]).stdout.strip()
            if running != b"true":
                raise RuntimeError("A capture helper did not start")
        env = "export DPT_CALL_DESTINATION=" + shlex.quote(profile["destination"]) + "\n"
        command("exec", "-i", "dpt-ims-ue-client", "sh", "-c",
                "umask 077; cat > /run/dpt-call-profile.env", input=env.encode())
        result = subprocess.run(["podman", "exec", "dpt-ims-ue-client", "sh", "-c",
            "umask 077; . /run/ims-client.env; . /run/dpt-call-profile.env; "
            "exec lua /opt/dpt_ue_call.lua"], capture_output=True, text=True, timeout=42)
        (folder / "ue-preflight.log").write_text(result.stdout + result.stderr)
        report["client_exit_code"] = result.returncode
        report["ue_events"] = [line for line in (result.stdout + result.stderr).splitlines()
                               if line.startswith(("DPT_REGISTERED", "DPT_REGISTRATION_FAILURE",
                                                   "DPT_SIP", "DPT_RESULT", "DPT_ERROR"))]
        events = log()[before:].decode(errors="replace")
        report["gateway_block_verified"] = "DPT_PREFLIGHT_BLOCKED" in events
        report["provider_dial_executed"] = bool(re.search(r"Executing.*Dial\(", events))
        report["provider_invites"] = provider_invites(events)
        report["sip_responses"] = sorted(set(re.findall(r"^SIP/2\.0 \d{3}[^\r\n]*",
                                                        events, re.M)))
        report["passed"] = (result.returncode == 0 and report["gateway_block_verified"]
                            and not report["provider_dial_executed"]
                            and report["provider_invites"] == 0)
    except Exception as error:
        report["error_type"] = type(error).__name__
    finally:
        command("exec", "dpt-sip-control-test", "asterisk", "-rx", "pjsip set logger off")
        if folder:
            capture, count = collect(folder)
            report.update(trace_folder=str(folder), combined_capture=str(capture),
                          capture_packets=count)
            (folder / "preflight-result.json").write_text(json.dumps(report, indent=2))
            (PRIVATE / "ims-client/latest-preflight-path").write_text(str(folder))
        (PRIVATE / "ims-client/call-preparation.json").write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
