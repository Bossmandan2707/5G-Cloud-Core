#!/usr/bin/env bash
# Step 0 - bottom of the stack: OS packages, kernel modules, sysctls.
# Target: openSUSE Leap 15.6+/Tumbleweed or SLES 15 SP5+ (zypper-based, systemd).
# SLE Micro / MicroOS are transactional: run the zypper line through
#   transactional-update pkg install ...   and reboot instead of using this script as-is.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }

echo "==> OS release"
grep -E '^(NAME|VERSION)=' /etc/os-release
uname -r

echo "==> Base packages"
zypper --non-interactive refresh
zypper --non-interactive install --no-recommends \
  iproute2 iptables nftables lksctp-tools curl jq ca-certificates

echo "==> Kernel modules (SCTP for N2/NGAP, tun for ogstun/uesimtun)"
cat >/etc/modules-load.d/open5gs.conf <<'EOF'
sctp
tun
EOF

load_mod() {
  modprobe "$1" 2>/dev/null && return 0
  return 1
}
for m in tun sctp; do
  if ! load_mod "$m"; then
    if [ "$m" = "sctp" ]; then
      # On some SUSE releases the sctp module ships in kernel-default-extra.
      echo "sctp not available - installing kernel-default-extra"
      zypper --non-interactive install kernel-default-extra || true
    fi
    load_mod "$m" || {
      echo "ERROR: cannot load kernel module '$m' for running kernel $(uname -r)."
      echo "       If a kernel package was just installed, reboot and re-run this script."
      exit 1
    }
  fi
  echo "module $m: loaded"
done

echo "==> Sysctls (forwarding for UE traffic leaving the UPF)"
cat >/etc/sysctl.d/90-open5gs.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl --system >/dev/null
echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward)"

echo "==> Security frameworks"
if command -v getenforce >/dev/null 2>&1; then echo "SELinux: $(getenforce)"; else echo "SELinux: not installed"; fi
if command -v aa-status >/dev/null 2>&1; then echo "AppArmor: $(aa-enabled 2>/dev/null || echo unknown)"; fi

echo "==> /dev/net/tun"
ls -l /dev/net/tun

echo "OK - OS bootstrap complete"
