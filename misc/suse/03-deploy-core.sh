#!/usr/bin/env bash
# Step 3 - deploy the 5G core (NRF, AMF, SMF, UPF, UDR, UDM, AUSF, PCF, MongoDB, subscriber
# provisioning, UERANSIM gNB) as pod "open5gs" with a fixed IP, then the UE as its own pod "ue".
#
# Two pods because the UE must NOT share a network namespace with the UPF: the UE address would
# be local to the UPF's namespace and return traffic on the Gi/N6 interface would never reach the
# GTP tunnel. The UE reaches the gNB's simulated radio link over the pod network instead.
#
# Rootful Podman is used on SUSE: the UPF/UE need /dev/net/tun + NET_ADMIN and the pod
# needs the net.ipv4.ip_forward sysctl, all of which are straightforward as root.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$HERE/.."
CORE_SPEC="${CORE_SPEC:-$ROOT/open5gs-pod.yaml}"
UE_SPEC="${UE_SPEC:-$ROOT/ue-pod.yaml}"
NET="${NET:-podman-default-kube-network}"
SUBNET="${SUBNET:-10.89.0.0/24}"
CORE_IP="${CORE_IP:-10.89.0.50}"   # must match gnbSearchList in ue-pod.yaml
for f in "$CORE_SPEC" "$UE_SPEC"; do [ -f "$f" ] || { echo "spec not found: $f"; exit 1; }; done

echo "==> Pre-flight"
for m in sctp tun; do lsmod | grep -q "^$m" || { echo "kernel module $m not loaded - run 00-bootstrap-os.sh"; exit 1; }; done
echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"
FREE_MB=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
echo "available memory: ${FREE_MB} MiB (the lab needs roughly 1 GiB)"

echo "==> Network $NET ($SUBNET) - fixed core IP $CORE_IP"
podman network exists "$NET" || podman network create --subnet "$SUBNET" "$NET"

echo "==> Deploying core pod (open5gs)"
podman kube play --replace --network "$NET" --ip "$CORE_IP" "$CORE_SPEC"

echo "==> Waiting for the staggered core startup (gNB starts after 20 s)"
sleep 45

echo "==> Deploying UE pod (ue)"
podman kube play --replace --network "$NET" "$UE_SPEC"
sleep 25

echo "==> Containers"
podman ps --filter pod=open5gs --filter pod=ue --format "table {{.Names}}\t{{.Status}}"

echo "==> Verifying"
"$HERE/99-verify.sh" podman
