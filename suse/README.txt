SUSE DEPLOYMENT KIT - 5G core lab (Open5GS 2.7.5 + UERANSIM 3.2.6)
===================================================================

STATUS
  * TESTED on macOS + Podman 5.8.8 (Intel): open5gs-pod.yaml, ue-pod.yaml, 99-verify.sh and the
    two-pod `podman kube play` flow used by 03-deploy-core.sh (incl. Gi/N6 egress via Wi-Fi).
  * UNTESTED on SUSE: everything SUSE-specific (zypper, firewalld, systemd units, k3s).
    Run it on a scratch VM first and read each script before running it as root.
  * Differences from the Mac: native Linux (no Podman VM), rootful Podman, kernel modules are
    loaded on the host, SUSE ships AppArmor (not SELinux) so the spc_t workaround is not needed
    (the setting is simply ignored).

TOPOLOGY (two pods)
  pod "open5gs"  fixed IP 10.89.0.50   NRF AMF SMF UPF UDR UDM AUSF PCF MongoDB gNB
                 N2/N3/N4/SBI all on loopback inside the pod; gNB radio link (UDP 4997) on eth0
  pod "ue"       own network namespace  UERANSIM UE -> uesimtun0 (10.45.0.x)
  Gi/N6 path:    UE -> radio sim -> gNB -> GTP-U -> UPF (ogstun 10.45.0.1/16) -> MASQUERADE ->
                 pod network -> host NAT -> host uplink (Wi-Fi on the Mac) -> internet
  Why two pods:  with the UE inside the UPF's namespace, 10.45.0.2 was a LOCAL address there and
                 return traffic on ogstun was never delivered into the GTP tunnel (100% loss).

LAYOUT
  open5gs-test/
    open5gs-pod.yaml              core: ConfigMap + Pod (NRF..PCF, MongoDB, provision, gNB)
    ue-pod.yaml                   UE: ConfigMap + Pod (separate network namespace)
    monitoring/                   exporter source (app.py, requirements.txt, Containerfile)
    tools/extract_attach_trace.py merge container logs into one chronological UE-attach trace
    suse/
      00-bootstrap-os.sh          zypper packages, sctp+tun modules (persisted), ip_forward sysctl
      01-install-container-runtime.sh   Podman/Buildah/Skopeo, Docker-compatible socket, smoke test
      02-firewall.sh              firewalld: SSH only by default, optional CIDR-limited rules
      03-deploy-core.sh           network + core pod (fixed IP) + UE pod, then 99-verify.sh
      04-autostart-systemd.sh     installs systemd/open5gs.service + open5gs-ue.service (boot start)
      05-monitoring-exporter.sh   build + run exporter on 127.0.0.1:8000 (restart=always)
      99-verify.sh                PASS/FAIL checks incl. Gi egress (podman | k8s modes)
      systemd/                    the two unit files
      k3s/10-install-k3s.sh       single-node Kubernetes (alternative to Podman)
      k3s/20-deploy-core.sh       core pod, then UE pod patched with the core pod's real IP

ORDER - Podman path
  sudo ./00-bootstrap-os.sh
  sudo ./01-install-container-runtime.sh
  sudo ./02-firewall.sh
  sudo ./03-deploy-core.sh            # manual run + verification
  sudo ./04-autostart-systemd.sh      # optional: replace manual run with boot-time services
  sudo ./05-monitoring-exporter.sh

ORDER - Kubernetes (k3s) path
  sudo ./00-bootstrap-os.sh
  sudo ./02-firewall.sh
  sudo ./k3s/10-install-k3s.sh
  sudo ./k3s/20-deploy-core.sh

EXPECTED RESULT (from the Mac run)
  NRF: 6 NF registrations | N4 PFCP associated | N2 NG Setup successful
  UE (IMSI 999050000000001, PLMN 999/05) registers, PDU session up, uesimtun0 = 10.45.0.x/32
  Gi: ping 8.8.8.8 through uesimtun0 ~6 ms, 0% loss; UE egress public IP == host uplink public IP;
      ~10 MB download at ~26 Mbit/s through the tunnel.

SUBSCRIBERS (provisioned by the "provision" container at pod start; MongoDB is not persisted)
  999050000000001                    active UE; copies the legacy lab subscriber's test profile
  998010000000001                    K/OPc = Open5GS public test values
  998010000074544  MSISDN 26774544   same test K/OPc
  Only 999050000000001 has an active UE definition (ue-pod.yaml).

KNOWN ISSUES
  1. UERANSIM radio-link loss: after ~8 minutes and a 10 MB download the gNB logged
     "UE[1] signal lost"; the UE then looped on Service Request and the gNB discarded it
     ("UE context already exists"), so Gi traffic stopped. Recreating the UE pod re-attached it.
     Likely a UERANSIM simulation limitation under load (not confirmed). Workaround:
       podman kube play --replace --network podman-default-kube-network ue-pod.yaml
  2. UERANSIM image has no CA bundle: use plain HTTP (or curl -k) when testing through uesimtun0.
  3. The UE gets the next free address each time (10.45.0.2, .3 ...) because the SMF allocates
     dynamically.
  4. The core uses loopback addresses and publishes no host ports. An external gNB cannot reach
     it until ports are published/re-addressed (02-firewall.sh already supports CIDR-limited rules).
  5. PCF logs "No [nbsf-management]" and SMF logs "No diameter configuration": harmless here
     (no BSF, no 4G Gx).
  6. SCTP: if `modprobe sctp` fails, install kernel-default-extra and reboot into the matching kernel.
  7. SLE Micro / MicroOS are transactional - use transactional-update instead of zypper installs.
  8. Image pulls come from docker.io (rate limits apply); mirror with skopeo for air-gapped hosts.
  9. Double NAT on Gi: UPF MASQUERADE, then the container network/host NAT. Fine for a lab.

DAY-TO-DAY
  Podman:   podman ps --filter pod=open5gs ; podman logs -f open5gs-amf ; podman logs -f ue-ue
            podman kube down open5gs-pod.yaml ; podman kube down ue-pod.yaml
  systemd:  systemctl status open5gs open5gs-ue ; journalctl -u open5gs -u open5gs-ue -f
  k3s:      kubectl -n open5gs get pods ; kubectl -n open5gs logs open5gs -c amf -f
  Gi test:  podman exec ue-ue curl -s --interface uesimtun0 http://api.ipify.org
