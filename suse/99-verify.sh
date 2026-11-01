#!/usr/bin/env bash
# Verify the lab (core pod "open5gs" + UE pod "ue"). Usage:
#   ./99-verify.sh podman              # Podman deployment (run as root on SUSE; rootless works on the Mac)
#   ./99-verify.sh k8s [namespace]     # k3s/Kubernetes deployment (default namespace: open5gs)
set -uo pipefail

MODE="${1:-podman}"
NS="${2:-open5gs}"

cname() { # logical name -> Podman container name
  case "$1" in ue) echo "ue-ue" ;; *) echo "open5gs-$1" ;; esac
}
logs() { # logs <container>
  case "$MODE" in
    podman) podman logs "$(cname "$1")" 2>&1 ;;
    k8s)
      if [ "$1" = ue ]; then kubectl -n "$NS" logs ue -c ue 2>&1
      else kubectl -n "$NS" logs open5gs -c "$1" 2>&1; fi ;;
    *) echo "unknown mode $MODE" >&2; exit 2 ;;
  esac
}
run() { # run <container> <shell command>
  local c="$1"; shift
  case "$MODE" in
    podman) podman exec "$(cname "$c")" sh -c "$*" 2>&1 ;;
    k8s)
      if [ "$c" = ue ]; then kubectl -n "$NS" exec ue -c ue -- sh -c "$*" 2>&1
      else kubectl -n "$NS" exec open5gs -c "$c" -- sh -c "$*" 2>&1; fi ;;
  esac
}

FAIL=0
check() { # check "<label>" "<shell expression evaluated here>"
  if eval "$2" >/dev/null 2>&1; then echo "PASS  $1"; else echo "FAIL  $1"; FAIL=1; fi
}

# count_matches avoids `grep -q` (it exits early and, with pipefail, the SIGPIPE on the log
# producer would be reported as a failure).
count_matches() { logs "$1" | grep -c "$2" || true; }

check "NRF has >= 6 NF registrations" '[ "$(count_matches nrf "NF registered")" -ge 6 ]'
check "N4: SMF<->UPF PFCP associated"  '[ "$(count_matches smf "PFCP associated")" -ge 1 ]'
check "N2: gNB NG Setup successful"    '[ "$(count_matches gnb "NG Setup procedure is successful")" -ge 1 ]'
check "UE registration successful"     '[ "$(count_matches ue "Initial Registration is successful")" -ge 1 ]'
check "PDU session established"        '[ "$(count_matches ue "PDU Session establishment is successful")" -ge 1 ]'

echo
echo "UE tunnel : $(run ue 'ip -br addr show uesimtun0' | head -n1)"
echo "UPF ogstun: $(run upf 'ip -br addr show ogstun' | head -n1)"
echo "ip_forward: $(run upf 'cat /proc/sys/net/ipv4/ip_forward')"

echo
echo "Gi / N6 user plane (UE -> GTP-U -> UPF -> NAT -> host uplink -> internet):"
check "Gi: ping 8.8.8.8 through uesimtun0" 'run ue "ping -c 3 -W 3 -I uesimtun0 8.8.8.8"'
# The UERANSIM image has no CA bundle, so use plain HTTP for the egress-IP check.
EGRESS="$(run ue 'curl -s -m 10 --interface uesimtun0 http://api.ipify.org' | tail -n1)"
check "Gi: HTTP through uesimtun0 returns an egress IP" '[[ "$EGRESS" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]'
echo "UE egress public IP: ${EGRESS:-<none>}   (should equal this host's uplink public IP)"

exit $FAIL
