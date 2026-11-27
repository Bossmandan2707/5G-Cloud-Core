# Dan Powell Technologies — UE Telemetry & MDM Dashboard

**From a connected UE to an observable device.**

I wanted to go beyond showing that my simulated 5G handset could register and reach the internet. I wanted to see what was happening at the UE itself: whether it was still connected, which address it had, how much traffic was passing through its tunnel, and whether a connectivity failure was real.

To achieve that, I built a read-only telemetry agent inside my UE pod and added a dedicated **UE MDM** tab to my monitoring dashboard.

## What I wanted

My aim was to answer these questions from one screen:

- Is my telemetry agent alive, and how recent are its measurements?
- Is the UE actually registered, or does it only have a tunnel interface left over?
- Does it have an active PDU session, and which DNN and IP address is it using?
- How much traffic is entering and leaving the UE tunnel?
- Are interface errors or dropped packets increasing?
- Can traffic really leave through the UE's 5G data path?
- How much CPU and memory are the UE container and telemetry agent using?
- Can I distinguish a network fault from missing or stale monitoring data?

I also wanted to keep the telemetry lightweight and avoid giving the agent access to SIM authentication information or control of the device.

## What I achieved

I deployed a telemetry sidecar named **`ue-mdm`** alongside my UERANSIM UE. It shares the UE pod's network namespace, so it can observe the same interfaces and tunnel without mounting the UE's authentication configuration.

I connected it to my **Dan Powell Technologies** dashboard and combined its measurements with live native UE status.

| What I can see | Information source |
|---|---|
| Agent heartbeat, uptime and sample age | Telemetry agent |
| Interface IP addresses, administrative state and MTU | Shared UE-pod network namespace |
| RX/TX bytes, packets, rates, errors and drops | UE-pod interface counters |
| Tunnel presence and source-routing information | Agent and Linux route metadata |
| UE-source TCP connectivity and handshake latency | Fixed, route-verified probe through the UE tunnel |
| Registration, connection mode, PLMN and TAC | Live UERANSIM `nr-cli status` |
| PDU-session state, DNN/APN and assigned IP | Live UERANSIM `nr-cli ps-list` |
| UE-container CPU, memory and process count | Podman |
| Agent CPU, RSS and memory limit | Agent process and its own cgroup |
| Recent traffic and connectivity charts | Bounded, in-memory dashboard history |
| MDM monitoring gauges | Existing Prometheus-compatible `/metrics` endpoint |

My active lab configuration is **IMSI `999050000000001`, MCC `999`, MNC `05`**. The UE tunnel IP is dynamically assigned and can change after reattachment; the dashboard reads it rather than assuming a fixed address.

## How it fits together

**UERANSIM UE + telemetry sidecar in the UE pod → read-only dashboard collector → UE MDM page and Prometheus-compatible metrics**

I keep three measurement scopes separate:

1. **Agent telemetry** describes the agent and shared pod network.
2. **Native UE state** describes registration and PDU sessions.
3. **UE-container resources** describe UERANSIM, not the Mac, Linux VM or sidecar.

A healthy agent does not automatically mean the UE has internet access, and an administratively UP tunnel does not prove a working data session.

## My dashboard links

With my lab and monitoring server running on my Mac:

- **[UE MDM telemetry](http://127.0.0.1:8000/mdm)**
- **[Core interface map](http://127.0.0.1:8000/interfaces)**
- **[Live GTP-U traces](http://127.0.0.1:8000/gtp)**
- **[Performance monitoring](http://127.0.0.1:8000/)**
- **[Prometheus-compatible metrics](http://127.0.0.1:8000/metrics)**

These are local links, not publicly hosted dashboards. Opening this README on another computer does not connect to my running lab.

The agent listens on **pod loopback `127.0.0.1:9108`**, which is not a browser URL on my Mac. The dashboard reads it using a fixed `podman exec` request, without publishing another host port.

## A connectivity check I can trust

The agent performs a small TCP handshake to **`1.1.1.1:443`** about every 30 seconds. It first verifies that the route from the UE tunnel IP uses the UE tunnel interface, then explicitly binds the connection to that IP.

If that route cannot be verified, the check is **skipped** rather than silently falling back to the pod uplink. The result is **TCP-handshake latency, not radio latency**. The probe generates a small amount of traffic and may wake an idle UE connection.

During load testing, I saw why this matters: the agent remained healthy and the UE could report registration while the simulated radio/data path had stalled. The TCP check and an independent tunnel ping both failed. After stopping the traffic test and restarting only the UE simulator, the check recovered from the newly assigned UE IP.

I did not hide the failure or force a green indicator. I used it to identify and verify recovery of a real data-path problem.

## Security and resource limits

I run the sidecar with:

- Non-root UID/GID **`10001:10001`**.
- A read-only root filesystem and all Linux capabilities dropped.
- No privilege escalation.
- A **96 MiB** memory limit and **0.2 CPU** limit.
- No published host port.
- No UE authentication-config, user host-filesystem or container-socket mount.

The dashboard uses selected native-status fields. It does not display authentication keys, raw UE logs, GUTI/SUCI or packet payloads.

## Building and running it

From the repository root:

```bash
podman build -t localhost/ue-mdm:0.1 telemetry/ue_mdm
```

The sidecar is included in [`ue-pod.yaml`](../../ue-pod.yaml), so I build its image before deploying or recreating the UE pod.

Replacing the UE pod interrupts its current session and removes helpers joined to it. To attach the agent to an existing pod without replacing the UE, I use the restricted command in the [main project README](../../README.md#my-ue-pod-mdm-telemetry-agent), only when `ue-mdm` does not already exist.

I start the monitoring server with the project's virtual environment:

```bash
.venv/bin/python -m pip install -r monitoring/requirements.txt
.venv/bin/python monitoring/dashboard.py
```

I do not start a second monitoring server when port 8000 is already occupied.

## How I validated it

I verified a fresh heartbeat, real tunnel observations, live native `RM-REGISTERED` state, an active PDU session, and a successful TCP check using the UE tunnel source IP. I also checked that UE-container resources and agent resources were reported separately.

The combined monitoring suite passed **62 tests**, covering source-bound probes, counter resets, missing/stale telemetry, safe field selection, interface-map status and HTTP routes:

```bash
.venv/bin/python -m unittest discover -s monitoring -p 'test_*.py' -v
```

## What this does not claim

This is **MDM-style telemetry for a simulated UE**, not a complete commercial mobile-device-management platform.

I have not implemented mobile OS enrollment, compliance enforcement, remote commands, software installation or device wipe. Battery, GPS/location and physical RF measurements such as RSRP, RSRQ and SINR are unavailable here and explicitly marked unsupported.

Containers in the UE pod share interface counters, so they do not represent only video traffic or one process. History is limited to the latest 120 dashboard samples, not a persistent telemetry database.

I expose Prometheus-compatible metrics, but that does not mean a standalone Prometheus server or Grafana is deployed.

---

**What I demonstrated:** I moved beyond a simple “UE connected” result and built visibility into device state, session state, traffic, resources and real connectivity—while keeping measurement scope, privacy and simulation limits clear.
