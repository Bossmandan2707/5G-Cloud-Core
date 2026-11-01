#!/usr/bin/env bash
# Step 5 - build and run the Python monitoring exporter (bound to localhost only).
# Probe more targets with:  TARGETS="http://a:7777,http://b:8080" ./05-monitoring-exporter.sh
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/../monitoring"
TARGETS="${TARGETS:-https://example.com}"

echo "==> Building py-monitor:0.1"
podman build -t py-monitor:0.1 -f "$SRC/Containerfile" "$SRC"

echo "==> (Re)starting container on 127.0.0.1:8000"
podman rm -f py-monitor >/dev/null 2>&1 || true
podman run -d --name py-monitor --restart=always -p 127.0.0.1:8000:8000 -e TARGETS="$TARGETS" py-monitor:0.1

sleep 6
curl -s http://127.0.0.1:8000/metrics | grep -E '^(host_|probe_)'
echo "OK - exporter running (not reachable from the LAN)"
