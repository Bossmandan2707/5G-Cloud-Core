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

## What I demonstrated

I demonstrated that my simulated UE could register with the 5G core, establish a PDU session, and reach the internet through the user plane.

I then verified that traffic using both component logs and live packet capture, and displayed the results in my monitoring dashboard.

I also prepared an alternative **SUSE deployment kit with k3s and systemd options**, although those were not the platform used for this demonstration.
