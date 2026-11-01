#!/usr/bin/env bash
# Step 2 - host firewall (firewalld, the SUSE default).
# Design: the 5G core runs inside one pod on loopback addresses and publishes NO host ports,
# so the host only needs SSH. Nothing is opened unless you set the optional variables below.
#
# Optional (only needed if you later publish ports for an EXTERNAL gNB / test UE):
#   EXTERNAL_RAN_CIDR=192.168.1.0/24  -> allow N2 (SCTP 38412) and N3 (UDP 2152) from that CIDR only
#   ALLOW_METRICS_CIDR=192.168.1.0/24 -> allow the exporter (TCP 8000) from that CIDR only
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }

echo "==> Installing/enabling firewalld"
zypper --non-interactive install --no-recommends firewalld
systemctl enable --now firewalld

ZONE=public
echo "==> Using zone: $ZONE"
firewall-cmd --set-default-zone="$ZONE"

# Never lock yourself out of a remote host.
if systemctl is-active --quiet sshd; then
  firewall-cmd --permanent --zone="$ZONE" --add-service=ssh
fi

if [ -n "${EXTERNAL_RAN_CIDR:-}" ]; then
  echo "==> Allowing N2/N3 from $EXTERNAL_RAN_CIDR"
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family=ipv4 source address=${EXTERNAL_RAN_CIDR} port port=38412 protocol=sctp accept"
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family=ipv4 source address=${EXTERNAL_RAN_CIDR} port port=2152 protocol=udp accept"
fi

if [ -n "${ALLOW_METRICS_CIDR:-}" ]; then
  echo "==> Allowing exporter :8000 from $ALLOW_METRICS_CIDR"
  firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="rule family=ipv4 source address=${ALLOW_METRICS_CIDR} port port=8000 protocol=tcp accept"
fi

firewall-cmd --reload

echo "==> Active configuration"
firewall-cmd --zone="$ZONE" --list-all
echo
echo "NOTE: Podman (netavark) manages its own forwarding/NAT rules through firewalld;"
echo "      container egress to the internet needs no extra rules here."
echo "OK - firewall configured"
