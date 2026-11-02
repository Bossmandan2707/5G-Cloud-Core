# Dan Powell Technologies — My 5G Lab

For this project, I built a containerized 5G lab, starting with my physical laptop and working through to live traffic tracing and performance monitoring.

## My hardware and operating system

I used my **Intel MacBook Pro**, which has an **Intel Core i7 processor and 16 GB of RAM**, running **macOS 15.7.9**.

Because the 5G software needs Linux, I used **Podman 5.8.8** to run a **Fedora CoreOS Linux virtual machine** through Apple’s hypervisor. I allocated the VM **four virtual CPUs, 2 GiB of RAM, and a 100 GiB virtual disk**.

Inside that VM, Podman manages my containers. It uses **crun** to run them and **Netavark** for container networking.

## How I deployed the lab

I defined the lab in **YAML files** and deployed it using **`podman kube play`**.

Although these files use Kubernetes-style definitions, my demonstration runs through Podman rather than a Kubernetes cluster.

I organised the network into two main pods:

- A **core pod**, containing the 5G core functions, subscriber database, and simulated base station.
- A separate **UE pod**, containing my simulated handset.

Separating the UE from the core was important because it made the UE’s traffic travel through the simulated radio link and GTP-U tunnel.

## My 5G core

I used **Open5GS 2.7.5** for the core network, with each network function running in its own container.

The main functions were:

- **AMF** — handles the UE’s registration and access to the network.
- **SMF** — establishes and manages the UE’s data session.
- **UPF** — forwards the UE’s actual internet traffic.
- **NRF** — allows the network functions to discover each other.
- **AUSF, UDM, and UDR** — support authentication and subscriber information.
- **PCF** — provides policy decisions.

I used **MongoDB 4.4** to store subscriber profiles, with **Open5GS DBCTL and MongoDB shell commands** to provision my test subscribers.

## My simulated base station and handset

I used **UERANSIM 3.2.6** to simulate both the **gNodeB**, which is the 5G base station, and the **UE**, which represents a handset.

My active test UE uses:

- **IMSI:** `999050000000001`
- **MCC:** `999`
- **MNC:** `05`

This is a software-based simulation. I did not use a physical handset, SIM card, or over-the-air radio connection.

## How I tested the traffic

Once the UE registered and established a data session, I tested internet access using **ping and curl**, explicitly sending the traffic through the UE tunnel.

I also used **yt-dlp**, running in a **Python 3.12-based helper container**, to download YouTube media through the UE connection. This generated streaming traffic for testing rather than playing the video on screen.

The traffic followed this path:

**UE → simulated radio link → gNodeB → GTP-U tunnel → UPF → NAT → my Mac’s Wi-Fi → internet**

Linux tunnel interfaces, IP forwarding, and **iptables NAT** provided the user-plane connectivity.

## How I traced the network

I used **tcpdump** in an **Alpine Linux capture-helper container** to watch GTP-U traffic between the gNodeB and UPF.

That let me see packet timestamps, source and destination addresses, direction, and packet sizes.

I used **Podman logs** to inspect events inside the UE and core functions, including registration, authentication, session establishment, and errors.

I also used a **Python trace-extraction script** to combine component logs into one chronological UE-attach timeline, and **AWK** for the command-line traffic-rate monitor.

I verified the UE’s IMSI through the core signaling logs. The GTP-U packet-header display does not independently identify the subscriber.

## My monitoring dashboard

I built a custom **Python, HTML, CSS, and JavaScript dashboard**, branded **Dan Powell Technologies**.

The dashboard runs directly on macOS using **Python 3.9.6**. It uses:

- **psutil** for my Mac’s CPU, memory, disk, and network measurements.
- **Podman stats** for container resource usage.
- **tcpdump capture data** for live GTP-U packet tables and uplink/downlink charts.
- The **Python Prometheus client** to expose Prometheus-compatible metrics.

I kept host performance and GTP-U traffic measurements separate so that general laptop activity would not be mistaken for UE throughput.

My current setup uses a **custom dashboard and a Prometheus-compatible metrics endpoint**, rather than a separate Prometheus server or Grafana installation.

## Running my dashboard locally

With the Podman VM and both lab pods running, I can start the dashboard from the repository root:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r monitoring/requirements.txt
podman build -t gtpu-mon:0.1 tools/gtpu-mon
.venv/bin/python monitoring/dashboard.py
```

- Performance: http://127.0.0.1:8000/
- Live GTP-U traces: http://127.0.0.1:8000/gtp
- Core interface map: http://127.0.0.1:8000/interfaces
- UE MDM telemetry: http://127.0.0.1:8000/mdm
- Prometheus-format metrics: http://127.0.0.1:8000/metrics

The dashboard binds to localhost only. It uses port 8000, so I do not run the legacy `py-monitor` exporter on that port at the same time. The capture helper is removed when the dashboard shuts down normally. Packet history is bounded and kept in memory, not saved as a packet archive.

I run the dashboard regression tests with:

```bash
.venv/bin/python -m unittest discover -s monitoring -p 'test_*.py' -v
```

## My interface map

The Interfaces tab maps N1, N2, N3, N4, N6, N7, N8, N10, N11, N12, N13, N15, N35 and NRF discovery reference points applicable to this lab. It lists both-end addresses, all configured core listeners, and device addresses in the core pod, UE pod, Linux VM and Mac.

It samples read-only device, socket, route, forwarding and NAT observations about every 15 seconds, marking samples older than 45 seconds stale. N1 and SBI reference points are logical; a listening endpoint is not proof of a service transaction. N2 is marked established only when a live SCTP association is observed. UDP bindings do not prove GTP-U traffic or PFCP association. N6 shows the UPF uplink and its data-network next hop, not a claim that the internet is reachable.

## My UE-pod MDM telemetry agent
**[Read my MDM project story: what I wanted and what I achieved](telemetry/ue_mdm/README.md).**

I run a read-only telemetry sidecar named `ue-mdm` inside the UE pod. It is **not** a full mobile-device-management enrollment or remote-control platform.

The UE manifest includes this image, so I build it before deploying/recreating the UE:

```bash
podman build -t localhost/ue-mdm:0.1 telemetry/ue_mdm
```

To attach it to an already running UE pod without restarting the UE, I use the following command only when `ue-mdm` does not already exist:

```bash
podman run -d --name ue-mdm --pod ue \
  --label io.dpt.ue-mdm=true \
  --cap-drop ALL --read-only --security-opt no-new-privileges \
  --pids-limit 64 --memory 96m --cpus 0.2 \
  -e UE_MDM_IMSI=999050000000001 \
  -e "LAB_NAME=Dan Powell Technologies" \
  localhost/ue-mdm:0.1
```

The image runs as non-root UID/GID `10001`. It mounts no UE authentication configuration, container socket or user host filesystem. Its JSON, health and Prometheus endpoints bind to **pod loopback** `127.0.0.1:9108`; no host port is published. The dashboard fetches them with a fixed read-only `podman exec` request. `9108` is not a host-browser URL.

The UE MDM tab shows:

- Agent heartbeat, uptime and self-resource usage.
- Shared UE-pod interface addresses, administrative state, counters, errors, drops and rates.
- Tunnel presence and source-routing metadata.
- A fixed TCP handshake to `1.1.1.1:443` about every 30 seconds, explicitly bound to the UE tunnel IP. It is skipped when the source route cannot be verified as the UE tunnel; it never falls back to the pod uplink.
- Live native `nr-cli` registration/connection state, PLMN/TAC and PDU-session/DNN/address details.
- Separate UERANSIM-container CPU and memory measurements from Podman.
- Bounded in-memory traffic/probe history and `ue_mdm_*` gauges at the existing `/metrics` endpoint.

The probe generates a small amount of real UE traffic and can wake an idle UE connection. Its latency is TCP-handshake latency, not RF latency. Helpers share the UE network namespace, so namespace counters are not exclusively one process's traffic.

Battery, GPS, physical RF signal measurements, mobile-OS compliance and remote control are unsupported by this simulated device. The dashboard does not fabricate them, and it does not expose GUTI/SUCI, authentication keys, raw UE logs or packet payloads. Stale/missing agent and native-state data are shown separately.

If I change the configured IMSI, I also update the sidecar's `UE_MDM_IMSI` environment metadata. The dashboard warns on an identity mismatch. The SUSE Podman deployment script builds the sidecar image if absent; k3s requires the image to be built/imported into the node's image store separately and remains untested here.

## My final deployment checks

Before presenting the lab, I run:

```bash
bash suse/99-verify.sh podman
curl --fail --silent --show-error http://127.0.0.1:8000/api/snapshot
curl --fail --silent --show-error http://127.0.0.1:8000/api/gtp
```

The verification script checks network-function registration, the SMF/UPF PFCP association, gNodeB setup, UE registration, PDU-session establishment, and ping/HTTP access through the UE tunnel. I expect every check to report `PASS`.

In the dashboards, I check that:

- The active configuration is IMSI `999050000000001`, MCC `999`, and two-digit MNC `05`.
- Host and container samples are updating, and GTP capture reports `live`.
- Uplink and downlink packet counters increase when I generate UE traffic. Zero current throughput is normal when the UE is idle.
- I distinguish configured subscriber identity from signaling evidence: GTP-U headers alone do not identify an IMSI.

The UE tunnel address is dynamically assigned, so it can change after a reattachment.

### Recovery and subscriber-data protection

If the simulated radio link stalls and the gNodeB reports a stale UE context, I stop any streaming test and recreate only the UE:

```bash
podman kube play --replace --network podman-default-kube-network ue-pod.yaml
bash suse/99-verify.sh podman
```

This interrupts the UE session and removes helpers joined to the UE pod, but leaves the core pod intact.

MongoDB currently has no persistent volume. Stopping a pod is different from deleting or recreating it: before replacing the core pod, I back up the database with `mongodump` and retain a tested restore procedure. I keep database backups and runtime logs local and out of Git. The manifests contain public lab-test subscriber credentials, not production SIM credentials.

### Safe shutdown and deployment scope

I stop the dashboard with **Ctrl+C** when running it in the foreground, or send **SIGTERM** to its verified process when running it in the background. Normal shutdown removes its temporary packet-capture helper. I then stop the lab pods:

```bash
podman pod stop ue
podman pod stop open5gs
```

This is a locally validated demonstration lab, not a production or highly available deployment. The SUSE-specific, systemd, and k3s paths remain untested on SUSE. The dashboard and metrics endpoint stay bound to localhost, and neither a Prometheus server nor Grafana is deployed.

## What I demonstrated

I demonstrated that my simulated UE could register with the 5G core, establish a PDU session, and reach the internet through the user plane.

I then verified that traffic using both component logs and live packet capture, and displayed the results in my monitoring dashboard.

I also prepared an alternative **SUSE deployment kit with k3s and systemd options**, although those were not the platform used for this demonstration.
