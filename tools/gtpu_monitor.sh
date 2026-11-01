#!/usr/bin/env bash
# Continuous GTP-U (N3) link monitor for the lab.
#
# Usage:  tools/gtpu_monitor.sh [seconds]      (0 or omitted = run until Ctrl+C)
#
# Joins the core pod ("open5gs") with a tiny alpine+tcpdump container and prints one row per
# second of uplink/downlink GTP-U packets and bit rates, then a summary when it stops.
# Works with rootless Podman on the Mac and rootful Podman on Linux (use sudo there).
set -uo pipefail

DUR="${1:-0}"
POD="${POD:-open5gs}"
IMG="gtpu-mon:0.1"
HERE="$(cd "$(dirname "$0")" && pwd)"

if ! podman image exists "$IMG"; then
  echo "building $IMG (first run only)..." >&2
  podman build -q -t "$IMG" "$HERE/gtpu-mon" >/dev/null || { echo "image build failed" >&2; exit 1; }
fi

TIMEOUT=""
[ "$DUR" -gt 0 ] 2>/dev/null && TIMEOUT="timeout $DUR"

# label=disable: SELinux (enforcing in the Podman VM) would otherwise block raw packet capture.
exec podman run --rm --pod "$POD" --cap-add NET_RAW --cap-add NET_ADMIN \
  --security-opt label=disable "$IMG" \
  sh -c "$TIMEOUT tcpdump -i lo -nn -l -tt -q udp port 2152 2>/dev/null | awk -f /gtpu_rates.awk"
