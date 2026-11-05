# Dan Powell Technologies — My Mobile IMS / VoNR Lab

**A small mobile IMS design prepared for attachment to my existing 5G core, with honest readiness monitoring.**

## What I wanted

I wanted to extend my Open5GS data lab with a mobile IMS network so I could work towards voice over 5G NR—not simply run a generic SIP server and call it VoNR.

I also wanted the deployment files in GitHub, a clear explanation in my own project documentation, and an IMS tab alongside my performance, GTP, interface-map and UE MDM dashboards.

## What I have prepared

| Item | Current result |
|---|---|
| IMS topology and reproducible source reference | Prepared and committed as configuration/code |
| IMS-only Compose generation | Validated for seven services; no replacement full core |
| Private service credentials and runtime files | Generated outside Git with restrictive permissions |
| Separate core integration overlay | Generated for review; **not applied** |
| IMS monitoring page and JSON endpoint | Implemented; reports actual inventory and unknown measurements |
| IMS containers and databases | **Not started** |
| IMS subscriber/AKA provisioning | **Not performed** |
| SIP/IMS registration, N5 and voice QoS | **Not verified** |
| RTP audio or a real handset VoNR call | **Not verified** |

The existing 2-GiB Podman VM and running internet core were not resized, restarted or replaced during preparation. My default remains a safe preparation stage, not a claim that a live IMS service is ready.

## My architecture

The IMS-only bundle contains:

- **P-CSCF:** the UE's first IMS signaling contact and N5 policy integration point.
- **I-CSCF:** IMS entry/routing and subscriber-server interrogation.
- **S-CSCF:** registration and IMS session control.
- **PyHSS:** IMS subscriber/authentication support, with its required Redis service in the reference image.
- **MySQL:** IMS configuration and registration databases.
- **DNS:** IMS service discovery and realm records.
- **RTPengine:** a userspace media relay, without kernel-module loading.

The intended signaling and media paths are:

**UE IMS DNN → UPF → P-CSCF → I-/S-CSCF ↔ PyHSS**

**P-CSCF → SCP → PCF / BSF for N5 policy integration**

**UE media ↔ UPF ↔ RTP relay ↔ called party**

My planned realm is **`ims.mnc005.mcc999.3gppnetwork.org`**. The two-digit MNC `05` is padded to three digits in the IMS DNS realm.

### Planned addressing

| Component | Planned address |
|---|---|
| IMS bridge | `10.90.0.0/24`, gateway `10.90.0.1` |
| Core's reviewed IMS-side interface / SCP | `10.90.0.2` |
| IMS SQL | `10.90.0.10` |
| IMS DNS | `10.90.0.11` |
| PyHSS | `10.90.0.12` |
| P-CSCF | `10.90.0.20` |
| I-CSCF | `10.90.0.21` |
| S-CSCF | `10.90.0.22` |
| RTP relay | `10.90.0.23` |
| Separate IMS UE pool | `10.46.0.0/16`, gateway `10.46.0.1` |

These are configuration targets, not a claim that the addresses or services are active. My original internet UE pool remains `10.45.0.0/16`.

## The reference I used

I based the preparation on [herlesupreeth/docker_open5gs](https://github.com/herlesupreeth/docker_open5gs), pinned to commit:

`39029beeaca390cc05737593d143f09d1729cf2d`

The archive's SHA-256 is recorded in [`reference.json`](reference.json) and checked before extraction. Archive traversal, symlinks/devices and oversized extraction are rejected. Upstream license notices remain in the private extracted source.

I select IMS services only. I do not run the reference's full Open5GS deployment over my existing core. I remove host-published ports and blanket privileged mode, constrain memory/CPU/process counts, reduce Kamailio process/memory defaults, and replace the media startup with a userspace relay.

This pins the reference source, **not every OS package or upstream base-image layer**. Before live activation I still need to record/review the built image identities and validate the adapted services.

## Preparing my files

From the repository root:

```bash
.venv/bin/python -m pip install -r ims/requirements.txt
.venv/bin/python -m ims.lab prepare
```

Preparation downloads and verifies source, generates fresh development service credentials, and writes the runtime bundle to:

`~/.config/dan-powell-technologies/ims-lab/`

Important files there are:

- `source/compose.ims.yaml` — private IMS-only Compose configuration.
- `source/.env` — private runtime environment.
- `core-ims.review.yaml` — a separate proposed core overlay.
- `service-credentials.json` — private service material, never a GitHub file.
- `preparation.json` — non-secret preparation status and outstanding validation.

Files are owner-readable/writable only; executable startup scripts are owner-executable. The runtime directory is owner-only. Preparation refuses a runtime directory inside this repository and refuses to overwrite an existing extracted source tree.

I do not print or upload the generated `.env`, expanded Compose output, database backup, SIM keys or service credential file. If I need a fresh review bundle, I choose a new private `--runtime` directory; the dashboard's default preparation indicator refers to the default directory above.

## What my core overlay proposes

The generated overlay:

1. Keeps the internet session pool and explicitly identifies its DNN.
2. Adds an `ims` session pool and a second UPF TUN interface, `ogstun2`.
3. Adds P-CSCF advertisement and IMS DNS settings to the SMF.
4. Adds SCP/BSF configuration and containers using the existing core image.
5. Adds UPF setup for the separate IMS gateway.

It does **not** attach a second network to the active core, configure subscribers, turn on validated voice support, or apply QoS policies automatically.

The core must be deliberately attached to both its existing network and the planned IMS bridge before using this overlay. The P-CSCF and media relay need routes back to the IMS UE pool through the UPF, without address translation that would break subscriber-IP policy correlation or IMS IPsec.

The overlay also changes the SMF's DNS list, so internet DNS must be regression-tested after any future activation. I must validate DNS recursion/forwarding, IMS SRV records, N5/SCP/BSF discovery and Open5GS 2.7.5 compatibility on the real deployment—not assume them from static YAML.

## Subscribers and my test SIM

[`subscriber.template.yaml`](subscriber.template.yaml) records intended identities and QoS targets. It is **not** an API request or an active subscriber record.

The proposed physical-test-SIM IMSI is `999050000000002`; it is separate from my existing simulated UE `999050000000001`.

Before provisioning, I must match:

- USIM/ISIM identity and authentication material.
- IMS private identity (IMPI), public identities (IMPU) and realm.
- Sequence-number state and authentication algorithm.
- Core and IMS-HSS subscriber records.
- IMS DNN, slice and phone carrier/IMS configuration.

The fresh physical-SIM profile remains private and is not imported or activated by this preparation. I must not substitute the public demonstration authentication values already present in the old simulator examples.

The target signaling and conversational-voice QoS classes are **5QI 5 and 5QI 1**. They are design targets, not applied policies. Successful SIP registration alone does not verify voice QoS or media.

## My monitoring

The new local page is **[IMS / VoNR readiness](http://127.0.0.1:8000/ims)**, with JSON at `/api/ims`.

It shows:

- Prepared realm, network and service addresses.
- Actual container states, including `not deployed`, `running`, `unknown` and `stale`.
- Local socket observations when a running service exposes suitable tooling.
- Explicitly unknown registration, Diameter, call and media counters until measured instrumentation is available.
- Separate acceptance gates for IMS-AKA, N5 policy authorization, voice QoS, bidirectional RTP and handset VoNR.

There are no start, stop or provisioning controls in the web page. Unknown is not zero, and a bound SIP listener is not a successful authenticated registration or call.

The page binds to my existing localhost monitoring service. These are local links, not dashboards hosted by GitHub.

## Before any live activation

My current VM has 2 GiB RAM. The startup guard rejects that capacity; I recommend **6 GiB** for this combined lab, with a minimum guard near 4 GiB. A RAM change requires separately approved downtime.

Before touching the core I must:

1. Back up the subscriber database and current configuration to a private location, and verify recovery.
2. Review/import the dual-network core overlay and preserve the internet DNN.
3. Build and validate the IMS images and their configuration, then record image identities.
4. Provision matching core and IMS subscribers using protected input.
5. Verify routing, DNS, P-CSCF discovery and N5 compatibility.
6. Complete the registration, QoS and media tests below.

The startup wrapper requires both `--allow-start` and `--core-integration-reviewed`, sufficient VM memory and a private `activation-approved.json` containing operator attestations for:

- `subscriber_backup_verified`
- `dual_network_core_applied`
- `ims_profiles_provisioned`
- `n5_compatibility_reviewed`

All four must be boolean `true`. Those acknowledgements are **not automatic evidence** and must not be set simply to bypass the safeguards. `prepare` never writes this approval file.

Only after the real reviews and prerequisites are complete would I use:

```bash
.venv/bin/python -m ims.lab start --allow-start --core-integration-reviewed
```

This is a future activation command, **not a step performed for this delivery**. It uses the project's pinned Compose provider. Do not execute it merely to make dashboard boxes green.

## Validation and what remains

I validated source pinning/checksums, IMS-only selection, secret-file permissions, archive safety, Compose parsing, generated shell syntax, the separate core overlay, startup guards and honest monitoring states.

I have **not** yet verified:

- Full adapted-container startup or Kamailio runtime configuration.
- Authenticated IMS-AKA registration.
- Correct IMS DNN/PCO behavior with a real phone.
- N5 policy authorization and voice QoS creation/removal.
- SIP call completion and bidirectional RTP/audio.
- Real handset VoNR.

I rerun the automated suite from the repository root:

```bash
.venv/bin/python -m unittest discover -s monitoring -p 'test_*.py' -v
```

A genuine VoNR demonstration requires a compatible 5G SA gNodeB, phone, provisioned test USIM/ISIM and suitable radio test environment. UERANSIM does not become a handset IMS client just because I add these servers. Wi-Fi access alone is not VoNR.

## Recovery and limits

For a future activated IMS stack, stop only the IMS Compose project while preserving its SQL volume. Do not use volume-deleting teardown as a recovery shortcut. Roll back core changes using the saved original manifest, original network attachment and tested subscriber backup—not by blindly replaying this candidate overlay.

This is a private lab candidate, not a carrier service. There is no public SIP trunk, PSTN interconnect, SMS service, emergency-calling support, lawful-intercept integration or production availability guarantee.

## Project files

- [`topology.yaml`](topology.yaml) — non-secret addresses and activation gates.
- [`reference.json`](reference.json) — pinned upstream source/hash.
- [`lab.py`](lab.py) — preparation, validation, core overlay and guarded start.
- [`subscriber.template.yaml`](subscriber.template.yaml) — unprovisioned identity/QoS design.
- [`../monitoring/ims_monitor.py`](../monitoring/ims_monitor.py) — read-only inventory collector.
- [`../monitoring/ims.html`](../monitoring/ims.html) — IMS dashboard.

## References and acknowledgements

- [docker_open5gs](https://github.com/herlesupreeth/docker_open5gs) — reference deployment; retain its BSD notices.
- [Kamailio's open-source VoNR demonstration](https://www.kamailio.org/w/2024/04/kamailio-powering-first-live-demo-of-5g-vonr-and-smsonr-with-oss-only/).
- [Open5GS Dockerized VoLTE tutorial](https://open5gs.org/open5gs/docs/tutorial/03-VoLTE-dockerized/) — related IMS background, not proof this VoNR adaptation works.

**What I achieved here:** a reproducible preparation workflow, a reviewable core attachment design and a monitoring page that distinguishes intent from measured service readiness, without disrupting my working data lab.
