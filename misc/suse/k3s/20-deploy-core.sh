#!/usr/bin/env bash
# Deploy the core to Kubernetes. The shared open5gs-pod.yaml is valid Kubernetes
# (ConfigMap + Pod), so the same file is applied unchanged into its own namespace.
#
# Notes:
#  - The pod uses hostPath /dev/net/tun, NET_ADMIN, runAsUser 0 and the net.ipv4.ip_forward
#    sysctl: the namespace is labelled "privileged" and k3s was configured (10-install-k3s.sh)
#    to allow that sysctl.
#  - seLinuxOptions in the spec is ignored on nodes without SELinux (default on SUSE).
#  - Bare Pods are used (not Deployments) to keep one shared network namespace per pod and
#    fixed names; delete + re-apply to restart. The UE is a second pod (ue-pod.yaml).
set -euo pipefail

export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SPEC="${SPEC:-$HERE/../../open5gs-pod.yaml}"
NS="${NS:-open5gs}"

echo "==> Namespace $NS (privileged pod-security)"
kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$NS" \
  pod-security.kubernetes.io/enforce=privileged \
  pod-security.kubernetes.io/warn=privileged \
  pod-security.kubernetes.io/audit=privileged --overwrite

echo "==> Server-side dry run"
kubectl -n "$NS" apply --dry-run=server -f "$SPEC"

echo "==> Applying (recreating the pod if it exists)"
kubectl -n "$NS" delete pod open5gs --ignore-not-found --wait=true
kubectl -n "$NS" apply -f "$SPEC"

echo "==> Waiting for the core pod (gNB starts after 20 s)"
kubectl -n "$NS" wait --for=condition=Ready pod/open5gs --timeout=300s || true
sleep 25

# The UE runs in its own pod (separate network namespace, see ue-pod.yaml). Kubernetes has no
# fixed pod IP, so point the UE at the core pod's actual IP (the gNB's radio link listens there).
UE_SPEC="${UE_SPEC:-$HERE/../../ue-pod.yaml}"
CORE_IP="$(kubectl -n "$NS" get pod open5gs -o jsonpath='{.status.podIP}')"
echo "==> Core pod IP: $CORE_IP - deploying UE pod"
kubectl -n "$NS" delete pod ue --ignore-not-found --wait=true
sed "s/10\.89\.0\.50/$CORE_IP/" "$UE_SPEC" | kubectl -n "$NS" apply -f -
kubectl -n "$NS" wait --for=condition=Ready pod/ue --timeout=120s || true
sleep 25

kubectl -n "$NS" get pods -o wide
echo "==> Verifying"
"$HERE/../99-verify.sh" k8s "$NS"
