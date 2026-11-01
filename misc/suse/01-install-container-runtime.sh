#!/usr/bin/env bash
# Step 1 - container runtime: Podman (rootful, native Linux - no VM like on macOS).
# Also enables the Docker-compatible API socket (equivalent of podman-mac-helper on the Mac).
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }

echo "==> Installing Podman toolchain"
zypper --non-interactive install --no-recommends podman buildah skopeo netavark aardvark-dns

echo "==> Versions"
podman --version
buildah --version | head -n1
skopeo --version

echo "==> Network backend (netavark expected)"
podman info --format '{{.Host.NetworkBackend}}'

echo "==> Docker-compatible API socket at /run/podman/podman.sock"
systemctl enable --now podman.socket
ln -sf /run/podman/podman.sock /var/run/docker.sock
curl -s --unix-socket /run/podman/podman.sock http://d/version | jq -r '"Engine: " + .Components[0].Name + " " + .Version + " | API " + .ApiVersion'

echo "==> Smoke test"
podman run --rm quay.io/podman/hello

echo "OK - container runtime ready"
