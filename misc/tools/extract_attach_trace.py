#!/usr/bin/env python3
"""Merge the lab's container logs into one chronological UE-attach trace.

Usage:  python3 tools/extract_attach_trace.py [output.txt]

Window: from the UE's first "Sending Initial Registration" to the first
"Connection setup for PDU session" (+/- 1 s margin). A separate section lists the
N2 (NG Setup) link bring-up. Works on `podman logs` of the open5gs-<name> containers.
"""
import re
import subprocess
import sys

CONTAINERS = ["gnb", "ue", "amf", "ausf", "udm", "udr", "pcf", "smf", "upf", "nrf"]
LABEL = {
    "gnb": "gNB ", "ue": "UE  ", "amf": "AMF ", "ausf": "AUSF", "udm": "UDM ",
    "udr": "UDR ", "pcf": "PCF ", "smf": "SMF ", "upf": "UPF ", "nrf": "NRF ",
}

UERANSIM = re.compile(r"^\[\d{4}-\d\d-\d\d (\d\d):(\d\d):(\d\d)\.(\d{3})\]\s*(.*)$")
OPEN5GS = re.compile(r"^\d\d/\d\d (\d\d):(\d\d):(\d\d)\.(\d{3}): (.*)$")
SRC_REF = re.compile(r"\s*\(\.\./[^)]*\)\s*$")  # trailing "(../src/amf/xxx.c:123)"
ANSI = re.compile(r"\x1b\[[0-9;]*m")  # Open5GS colours its log level/time/component

NOISE = (
    "UnRef NF EndPoint", "Setup NF EndPoint", "Open5GS daemon", "Configuration:",
    "metrics_server", "NF registered", "Heartbeat", "NRF-profile-get",
    "Try to discover", "has already been added",
)
N2_SETUP = ("NG Setup", "SCTP connection", "Trying to establish SCTP", "gNB-N2",
            "Number of gNBs", "SCTP association setup")


def to_ms(h, m, s, ms):
    return ((int(h) * 60 + int(m)) * 60 + int(s)) * 1000 + int(ms)


def fmt(ms):
    h, rem = divmod(ms, 3_600_000)
    m, rem = divmod(rem, 60_000)
    s, ms = divmod(rem, 1000)
    return f"{h:02d}:{m:02d}:{s:02d}.{ms:03d}"


def container_name(name):
    # the UE runs in its own pod (ue-pod.yaml); every other NF/gNB is in the open5gs pod
    return "ue-ue" if name == "ue" else f"open5gs-{name}"


def parse(name):
    out = subprocess.run(["podman", "logs", container_name(name)], capture_output=True, text=True)
    rows = []
    for line in (out.stdout + out.stderr).splitlines():
        line = ANSI.sub("", line)
        for rx in (UERANSIM, OPEN5GS):
            mt = rx.match(line)
            if mt:
                t = to_ms(*mt.groups()[:4])
                rows.append((t, name, SRC_REF.sub("", mt.group(5)).strip()))
                break
    return rows


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else None
    data = {c: parse(c) for c in CONTAINERS}

    ue = data["ue"]
    t0 = next((t for t, _, m in ue if "Sending Initial Registration" in m), None)
    t1 = next((t for t, _, m in ue if "Connection setup for PDU session" in m and t >= (t0 or 0)), None)
    if t0 is None:
        sys.exit("No 'Sending Initial Registration' found in the UE log - is the lab running?")
    t1 = t1 if t1 is not None else t0 + 5000
    lo, hi = t0 - 1000, t1 + 1000

    lines = []
    lines.append("UE ATTACH TRACE  (gNB <-> AMF <-> AUSF/UDM/UDR/PCF <-> SMF <-> UPF)")
    lines.append(f"Window: {fmt(lo)} - {fmt(hi)} (container clock, UTC)   UE: imsi-999050000000001, PLMN 999/05")
    lines.append("")
    lines.append("=== 1. N2 LINK SETUP (gNB -> AMF, SCTP 38412, NGAP NG Setup) ===")
    n2 = sorted((t, n, m) for n in ("gnb", "amf") for t, _, m in data[n] if any(k in m for k in N2_SETUP))
    for t, n, m in n2:
        lines.append(f"{fmt(t)}  {LABEL[n]}  {m}")

    lines.append("")
    lines.append("=== 2. UE ATTACH (RRC -> NAS Registration -> Authentication -> Security Mode -> PDU Session) ===")
    merged = sorted(
        ((t, n, m) for n in CONTAINERS for t, _, m in data[n]
         if lo <= t <= hi and not any(k in m for k in NOISE)),
        key=lambda r: r[0],
    )
    prev = None
    for t, n, m in merged:
        gap = "" if prev is None else f"  (+{t - prev} ms)"
        lines.append(f"{fmt(t)}  {LABEL[n]}  {m}{gap}")
        prev = t
    lines.append("")
    lines.append(f"Attach duration (Initial Registration -> PDU session up): {t1 - t0} ms")

    text = "\n".join(lines) + "\n"
    if out_path:
        with open(out_path, "w") as fh:
            fh.write(text)
        print(f"wrote {out_path} ({len(lines)} lines)")
    else:
        print(text)


if __name__ == "__main__":
    main()
