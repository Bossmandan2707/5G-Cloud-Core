#!/usr/bin/env bash
# Step 4 - run the lab under systemd so it starts at boot.
# Use INSTEAD of running 03-deploy-core.sh by hand (it replaces the manually started pods).
#
# Plain systemd units wrapping the exact `podman kube play` commands that were tested are used
# rather than Quadlet: the core pod needs a fixed IP (--ip) and Quadlet's support for that
# option varies by Podman version.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/.."

echo "==> Stopping any manually started pods"
podman kube down "$ROOT/ue-pod.yaml" >/dev/null 2>&1 || true
podman kube down "$ROOT/open5gs-pod.yaml" >/dev/null 2>&1 || true

echo "==> Installing specs and units"
install -d /opt/open5gs
install -m 0644 "$ROOT/open5gs-pod.yaml" /opt/open5gs/open5gs-pod.yaml
install -m 0644 "$ROOT/ue-pod.yaml"      /opt/open5gs/ue-pod.yaml
install -m 0644 "$HERE/systemd/open5gs.service"    /etc/systemd/system/open5gs.service
install -m 0644 "$HERE/systemd/open5gs-ue.service" /etc/systemd/system/open5gs-ue.service

systemctl daemon-reload
systemctl enable --now open5gs.service open5gs-ue.service

echo "==> Status"
systemctl --no-pager --full status open5gs.service open5gs-ue.service | head -n 24
echo
echo "Logs:   journalctl -u open5gs -u open5gs-ue -f"
echo "Verify: $HERE/99-verify.sh podman   (after ~2 minutes)"
