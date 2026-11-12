"""Bounded SIP/NGAP captures; packet payloads and credentials never go to stdout."""
import argparse
import datetime
import json
import os
import re
import struct
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
POINTS = (
    ("n2", ["--pod", "open5gs"], "sctp port 38412"),
    ("ue", ["--pod", "ue"], "host 10.90.0.20 and (udp or tcp or ip proto 50)"),
    ("pcscf", ["--network", "container:dpt-ims-pcscf"],
     "(udp or tcp) and (port 5060 or port 4060 or port 6060 or port 4500) or ip proto 50"),
    ("scscf", ["--network", "container:dpt-ims-scscf"],
     "(udp or tcp) and (port 5060 or port 4060 or port 6060)"),
    ("b2bua", ["--network", "container:dpt-sip-control-test"],
     "(udp or tcp) and (port 5060 or port 5061 or port 5063)"),
    ("hss", ["--network", "container:dpt-ims-pyhss"], "tcp port 3868"),
)


def command(*args, check=True):
    return subprocess.run(["podman", *args], capture_output=True, check=check)


def block(kind, body):
    body += b"\0" * (-len(body) % 4)
    size = len(body) + 12
    return struct.pack("<II", kind, size) + body + struct.pack("<I", size)


def combine(captures, destination):
    """Convert timestamp-sorted classic pcaps into distinct PCAPNG interfaces."""
    interfaces, records = [], []
    for point, paths in captures:
        interface = len(interfaces)
        link = None
        for path in paths:
            data = Path(path).read_bytes()
            if len(data) < 24:
                raise ValueError("Incomplete capture header")
            formats = {
                "d4c3b2a1": ("<", 1), "a1b2c3d4": (">", 1),
                "4d3cb2a1": ("<", 1000), "a1b23c4d": (">", 1000),
            }
            if data[:4].hex() not in formats:
                raise ValueError("Unsupported capture format")
            endian, divisor = formats[data[:4].hex()]
            current = struct.unpack(endian + "I", data[20:24])[0]
            if link is not None and link != current:
                raise ValueError("Point link type changed")
            link = current
            offset = 24
            while offset < len(data):
                if offset + 16 > len(data):
                    raise ValueError("Incomplete packet header")
                sec, fraction, size, original = struct.unpack(
                    endian + "IIII", data[offset:offset + 16])
                offset += 16
                if size > 16 * 1024 * 1024 or offset + size > len(data):
                    raise ValueError("Incomplete or oversized packet")
                records.append((sec * 1000000 + fraction // divisor, interface,
                                data[offset:offset + size], original))
                offset += size
        if link is None:
            raise ValueError("Missing capture for point")
        interfaces.append((point, link))
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
        for point, link in interfaces:
            name = point.encode()
            options = struct.pack("<HH", 2, len(name)) + name
            options += b"\0" * (-len(name) % 4) + struct.pack("<HH", 0, 0)
            output.write(block(1, struct.pack("<HHI", link, 0, 262144) + options))
        for timestamp, interface, packet, original in sorted(records, key=lambda r: r[0]):
            output.write(block(6, struct.pack("<IIIII", interface,
                timestamp >> 32, timestamp & 0xFFFFFFFF, len(packet), original) + packet))
    Path(destination).chmod(0o600)
    return len(records)


def start(seconds=90):
    if type(seconds) is not int or not 1 <= seconds <= 900:
        raise ValueError("Capture duration must be 1..900 seconds")
    os.umask(0o077)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    folder = Path.home() / ".config/dan-powell-technologies/traces" / ("call-" + stamp)
    if ROOT == folder.resolve() or ROOT in folder.resolve().parents:
        raise ValueError("Captures must remain outside the repository")
    folder.mkdir(parents=True, mode=0o700)
    session = {"state": "capturing", "seconds": seconds, "points": []}
    try:
        for name, network, expression in POINTS:
            container = "dpt-call-trace-" + name + "-" + stamp.lower()
            command("run", "-d", "--name", container, *network,
                "--cap-add", "NET_RAW", "--security-opt", "label=disable",
                "--memory", "64m", "--pids-limit", "32", "--entrypoint", "sh",
                "localhost/gtpu-mon:0.1", "-c",
                'umask 077; exec timeout -s INT "$1" tcpdump -Z root -p -i any '
                '-nn -s 0 -U -C 5 -W 2 -w /tmp/trace.pcap "$2"',
                "capture", str(seconds), expression)
            session["points"].append({"name": name, "container": container})
        (folder / "session.json").write_text(json.dumps(session, indent=2))
        return folder
    except Exception:
        for point in session["points"]:
            command("stop", "--time", "3", point["container"], check=False)
        raise


def collect(folder):
    folder = Path(folder).expanduser().resolve()
    expected = (Path.home() / ".config/dan-powell-technologies/traces").resolve()
    if folder.parent != expected or ROOT == folder or ROOT in folder.parents:
        raise ValueError("Only private lab trace sessions can be collected")
    session = json.loads((folder / "session.json").read_text())
    for point in session["points"]:
        if not re.fullmatch(r"dpt-call-trace-(n2|ue|pcscf|scscf|b2bua|hss)-\d{8}t\d{6}z",
                            point["container"]):
            raise ValueError("Unexpected capture helper")
        if point["name"] not in {p[0] for p in POINTS}:
            raise ValueError("Unexpected capture point")
    captures = []
    for point in session["points"]:
        command("stop", "--time", "3", point["container"], check=False)
        target = folder / point["name"]
        target.mkdir(mode=0o700, exist_ok=True)
        command("cp", point["container"] + ":/tmp/.", str(target))
        paths = sorted(target.glob("trace.pcap*"))
        for path in paths:
            path.chmod(0o600)
        captures.append((point["name"], paths))
    destination = folder / "combined-sip-n1-n2.pcapng"
    count = combine(captures, destination)
    session.update(state="collected", packets=count, combined=destination.name)
    (folder / "session.json").write_text(json.dumps(session, indent=2))
    return destination, count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("start", "collect"))
    parser.add_argument("folder", nargs="?")
    parser.add_argument("--seconds", type=int, default=90)
    args = parser.parse_args()
    if args.action == "start":
        print(start(args.seconds))
    elif args.folder:
        destination, count = collect(args.folder)
        print(json.dumps({"capture": str(destination), "packets": count}))
    else:
        parser.error("collect requires the private session folder")


if __name__ == "__main__":
    main()
