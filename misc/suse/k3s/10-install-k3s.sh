#!/usr/bin/env bash
# Kubernetes path (alternative to Podman): single-node k3s on SUSE.
# Run 00-bootstrap-os.sh first (kernel modules + sysctls). Podman is NOT required for this path.
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo $0)"; exit 1; }

K3S_CHANNEL="${K3S_CHANNEL:-stable}"

echo "==> firewalld: trust pod/service CIDRs (documented k3s requirement when firewalld is active)"
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --zone=trusted --add-source=10.42.0.0/16   # pods
  firewall-cmd --permanent --zone=trusted --add-source=10.43.0.0/16   # services
  firewall-cmd --reload
fi

echo "==> k3s config: allow the net.ipv4.ip_forward pod sysctl used by the UPF"
install -d /etc/rancher/k3s
cat >/etc/rancher/k3s/config.yaml <<'EOF'
write-kubeconfig-mode: "0640"
kubelet-arg:
  - "allowed-unsafe-sysctls=net.ipv4.ip_forward"
EOF

echo "==> Installing k3s (channel: $K3S_CHANNEL)"
curl -sfL https://get.k3s.io | INSTALL_K3S_CHANNEL="$K3S_CHANNEL" sh -

echo "==> Waiting for the node"
until k3s kubectl get nodes 2>/dev/null | grep -q ' Ready'; do sleep 3; done
k3s kubectl get nodes -o wide

echo "==> kubectl convenience"
ln -sf /usr/local/bin/k3s /usr/local/bin/kubectl 2>/dev/null || true
echo "Kubeconfig: /etc/rancher/k3s/k3s.yaml  (export KUBECONFIG=/etc/rancher/k3s/k3s.yaml)"
echo "OK - k3s ready. Next: ./20-deploy-core.sh"
