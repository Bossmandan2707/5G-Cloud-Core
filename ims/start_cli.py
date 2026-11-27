"""Resume the saved known-good lab; no call origination or AI-driven changes."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from ims.call_cli import ensure_gateway, readiness
from ims.call_prep import load_profile
from ims.runtime import PRIVATE, inspect, running, up

MODULE = "/usr/local/lib64/kamailio/modules/ims_ipsec_pcscf.so"


def verify_module(restore_stopped=False):
    pointer = PRIVATE / "known-good/current"
    if not pointer.exists():
        return {"verified": False, "reason": "Known-good checkpoint not saved yet"}
    folder = Path(pointer.read_text().strip()).resolve()
    if folder.parent != (PRIVATE / "known-good").resolve():
        raise ValueError("Unexpected recovery checkpoint")
    manifest = json.loads((folder / "manifest.json").read_text())
    data = inspect("dpt-ims-pcscf")
    if not data or data["Image"] != manifest["pcscf_image_id"]:
        raise RuntimeError("P-CSCF image differs from the frozen working baseline")
    if running("dpt-ims-pcscf"):
        result = subprocess.run(["podman", "exec", "dpt-ims-pcscf", "sha256sum", MODULE],
                                capture_output=True, text=True, check=True, timeout=10)
        if result.stdout.split()[0] != manifest["module_sha256"]:
            raise RuntimeError("Running P-CSCF module differs from the frozen baseline; refusing to alter it")
    elif restore_stopped:
        binary = folder / "ims_ipsec_pcscf.so"
        if hashlib.sha256(binary.read_bytes()).hexdigest() != manifest["module_sha256"]:
            raise RuntimeError("Frozen recovery module checksum failed")
        subprocess.run(["podman", "cp", str(binary), "dpt-ims-pcscf:" + MODULE],
                       capture_output=True, check=True, timeout=15)
    else:
        return {"verified": False, "reason": "P-CSCF is stopped; run network-start"}
    return {"verified": True, "module_sha256": manifest["module_sha256"]}


def ensure_machine():
    result = subprocess.run(["podman", "info", "--format", "{{.Host.Hostname}}"],
                            capture_output=True, timeout=15)
    if result.returncode == 0:
        return
    result = subprocess.run(["podman", "machine", "list", "--format", "json"],
                            capture_output=True, check=True, timeout=10)
    machines = json.loads(result.stdout)
    chosen = next((m for m in machines if m.get("Default")), None)
    if not chosen:
        raise RuntimeError("Existing lab VM unavailable; startup will not initialize or replace one")
    if not chosen.get("Running"):
        subprocess.run(["podman", "machine", "start", chosen["Name"]], check=True, timeout=90)


def resume(repair_ue=False):
    ensure_machine()
    module = verify_module(restore_stopped=True)
    if not module["verified"]:
        raise RuntimeError(module["reason"])
    result = up(repair_ue)
    ensure_gateway()
    checked = readiness(load_profile(PRIVATE / "sip-control-test/call-test.json"))
    if not checked["ready"]:
        raise RuntimeError("; ".join(checked["errors"]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repair-ue", action="store_true",
                        help="Explicit bounded reconnect of the idle simulated radio/UE")
    args = parser.parse_args()
    try:
        result = resume(args.repair_ue)
        print("NETWORK READY")
        print("IMS MSISDN: " + result["msisdn"])
        print("Internet: " + result["sessions"]["internet"]["address"])
        print("IMS: " + result["sessions"]["ims"]["address"])
        print("P-CSCF/S-CSCF registration and negotiated peer SPIs verified.")
        print("B2BUA ready; no call requested. Run ue-call --check before dialing.")
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print("network-start: " + str(error))
        return 2
