# Dan Powell Technologies — My Mobile IMS / VoNR Lab

**My running mobile IMS lab, with verified simulated-UE registration and honest limits on what I have tested.**

## What I wanted

I wanted to extend my Open5GS data lab with a mobile IMS network so I could work towards voice over 5G NR—not simply run a generic SIP server and call it VoNR.

I also wanted the deployment files in GitHub, a clear explanation in my own project documentation, and an IMS tab alongside my performance, GTP, interface-map and UE MDM dashboards.

## What I have verified

| Item | Current result |
|---|---|
| IMS topology and pinned reference | Configured for the branded PLMN-derived realm |
| IMS services and databases | Running alongside my existing core |
| Simulated UE sessions | Internet `10.45.0.2` and IMS `10.46.0.2` active |
| IMS registration | IMS-AKA and protected REGISTER/200 OK over IPsec verified; the probe deregistered cleanly |
| Diameter peers | I-CSCF and S-CSCF connected to the HSS in the new realm |
| Private IMS DNS | A/SRV queries from `10.46.0.2` verified after a DNS restart |
| Standalone SIP trunk call | SIPp → Asterisk B2BUA → Telnyx call setup and teardown verified separately |
| IMS-to-Telnyx call, voice QoS and audio | **Not yet verified end to end** |
| Physical-handset VoNR | **Not verified** |

These are lab observations from 6 November 2026, not a claim that a fresh checkout automatically reproduces the private runtime. My original preparation was non-disruptive; activation later included a VM memory increase and core integration. The realm migration and DNS-route repair described below did **not** restart the core or UE simulator.

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

My configured lab realm is **`bossman.ims.mnc005.mcc999.3gppnetwork.org`**. The standard PLMN-derived realm is `ims.mnc005.mcc999.3gppnetwork.org`: the two-digit MNC `05` is padded to three digits.

The `bossman` prefix is a custom private-lab subdomain, not a performance optimization or a guarantee of automatic handset discovery. My IMS DNS, subscriber identities and UE client must explicitly agree on this realm. The external Telnyx caller identity remains separate from the IMS realm.

### Configured addressing

| Component | Configured address |
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

The simulated UE uses `10.46.0.2` for IMS. My original internet UE pool remains `10.45.0.0/16`. An assigned address or running process alone does not establish registration, QoS or media readiness.

## The reference I used

I based the preparation on [herlesupreeth/docker_open5gs](https://github.com/herlesupreeth/docker_open5gs), pinned to commit:

`39029beeaca390cc05737593d143f09d1729cf2d`

The archive's SHA-256 is recorded in [`reference.json`](reference.json) and checked before extraction. Archive traversal, symlinks/devices and oversized extraction are rejected. Upstream license notices remain in the private extracted source.

I select IMS services only. I do not run the reference's full Open5GS deployment over my existing core. I remove host-published ports and blanket privileged mode, constrain memory/CPU/process counts, reduce Kamailio process/memory defaults, and replace the media startup with a userspace relay.

This pins the reference source, **not every OS package or upstream base-image layer**. Built-image/runtime identities remain in my private operational records.

## Preparing my files

From the repository root:

```bash
.venv/bin/python -m pip install -r ims/requirements.txt
.venv/bin/python -m ims.lab prepare
```

This is a **fresh preparation command, not the migration command for an existing lab**. Preparation downloads and verifies source, generates fresh development service credentials, and writes the runtime bundle to:

`~/.config/dan-powell-technologies/ims-lab/`

Important files there are:

- `source/compose.ims.yaml` — private IMS-only Compose configuration.
- `source/.env` — private runtime environment.
- `core-ims.review.yaml` — a separate proposed core overlay.
- `service-credentials.json` — private service material, never a GitHub file.
- `preparation.json` — non-secret preparation status and outstanding validation.

Files are owner-readable/writable only; executable startup scripts are owner-executable. The runtime directory is owner-only. Preparation refuses a runtime directory inside this repository and refuses to overwrite an existing extracted source tree.

I do not print or upload generated environment files, expanded Compose/container-inspect output, database backups, SIM keys or service credentials. If I need a fresh review bundle, I choose a new private `--runtime` directory; `prepare` is not an in-place updater.

## Realm migration and DNS return-route repair

I migrated from `bossman.dk.net` to **`bossman.ims.mnc005.mcc999.3gppnetwork.org`**, then repaired the DNS return path. This is the sequence I used; it is an operator procedure for the existing private deployment, not a turnkey migration subcommand.

### 1. Back up the working deployment

Before changing runtime files, I saved protected copies of:

- The private `source/` tree and service environment files.
- The affected containers' full settings, including their existing images, mounts, IP addresses, resource limits, capabilities and DNS settings.
- A verified IMS MySQL dump, the HSS subscriber record, the custom iFC XML and the UE client's environment.
- The actual generated CSCF/HSS configuration, so recreation would preserve the working N5/IPsec adaptations rather than revert to older preparation templates.

Realm backups are under `~/.config/dan-powell-technologies/ims-lab/backups/realm-20261106T085057Z/`. The later DNS-only backup is under `backups/dns-route-20261106T085946Z/`. These directories and their contents stay outside Git. Full container-inspect records and database dumps can contain credentials; I never paste them into the terminal, documentation or a pull request.

### 2. Align the realm and subscriber identities

I updated `topology.yaml`, `subscriber.template.yaml`, private `DPT_IMS_REALM` / `NETWORK_NAME` settings, DNS zones, SIP/Diameter identities and the UE client's `IMS_REALM` together. PLMN `999/05`, DNN `ims`, the existing subscriber keys and all service addresses were unchanged.

For IMSI `999050000000001`, the private identity is now `999050000000001@bossman.ims.mnc005.mcc999.3gppnetwork.org`. Its SIP public identities use the same realm; its existing lab telephone identity remains `tel:+4599999977`.

The HSS required two related corrections discovered during registration:

- Its Jinja loader searches under `/pyhss`; an absolute `ifc_path` such as `/pyhss/default_ifc.xml` does not load through that loader. I use the relative filename **`dpt-bossman-ifc.xml`**.
- The stock iFC returns identities in the unbranded 3GPP realm and references example application servers. I supplied a subscriber-specific profile matching the configured identities, without references to undeployed example services.

The private profile is stored in `source/pyhss/dpt-bossman-ifc.xml`, and the private HSS init script copies it into `/pyhss/` before starting the service. This prevents the profile from disappearing when the HSS container is recreated. `prepare` alone does not provision this subscriber or create that private profile.

I also updated the persisted I-CSCF routing data: `icscf.nds_trusted_domains.trusted_domain` and `icscf.s_cscf.s_cscf_uri` must refer to the new realm and `sip:scscf.bossman.ims.mnc005.mcc999.3gppnetwork.org:6060`. Changing only environment variables would leave old database routes behind.

### 3. Recreate only realm-dependent services

I stopped and retained the original DNS, PyHSS, P-CSCF, I-CSCF and S-CSCF containers, then recreated those services with the new realm and their existing operational settings. Original containers remain stopped for rollback.

I did **not** restart the core, UE simulator, MySQL or RTP relay for this migration. I did not run a full-core Compose deployment or delete a persistent volume.

The external trunk is separate: Asterisk's Telnyx-facing **From and P-Asserted-Identity remain `+13238801734`**. I did not replace the UE's IMS identity or change trunk credentials to perform the realm migration.

The current outbound test destination is kept outside Git in `~/.config/dan-powell-technologies/sip-control-test/call-test.json` and in the test B2BUA's allowlisted dialplan. Updating that setting does not place a call; automatic dialing is disabled. Future tests must read the current private destination rather than reuse a number from an earlier trace or command.

Packet captures and authentication diagnostics also stay private. N1 NAS is carried inside N2 NGAP and may be encrypted; provider SIP over TLS needs sanitized endpoint logs for correlation. A timestamp-merged capture is not proof that encrypted NAS or TLS has been decoded. I restart the bounded trace window before a new call rather than assume an earlier 15-minute capture is still running.

### 4. Persist the DNS return route

The DNS service at `10.90.0.11` originally had only its bridge/default routes. It could answer IMS-side queries, but could not return responses to the IMS UE pool through the UPF.

Its startup now runs this before BIND starts:

```sh
ip route replace "${UE_IPV4_IMS:?IMS UE subnet required}" via "${UPF_IP:?UPF address required}" || exit 1
```

For this lab, the values are `UE_IPV4_IMS=10.46.0.0/16` and `UPF_IP=10.90.0.2`. The DNS service has `NET_ADMIN` for route setup in its container network namespace, not blanket privileged mode. The updated preparation code and private Compose configuration both retain this requirement.

I backed up and recreated **DNS only**, then restarted it again to verify persistence. No NAT rule or core/UE restart was needed.

### 5. Verify from the actual IMS UE path

These are safe read-only route and peer checks:

```sh
podman exec dpt-ims-dns ip route get 10.46.0.2
podman exec ue-ue ip route get 10.90.0.11 from 10.46.0.2
podman exec dpt-ims-icscf kamcmd cdp.list_peers
podman exec dpt-ims-scscf kamcmd cdp.list_peers
podman exec ue-ue ping -I uesimtun0 -c 2 -W 2 1.1.1.1
```

The DNS route must use `10.90.0.2`. Both CSCF Diameter peers must identify `hss.bossman.ims.mnc005.mcc999.3gppnetwork.org` and be open.

I sent DNS queries with a socket explicitly bound to **`10.46.0.2`**, not just from an IMS server. After the DNS restart, these returned:

- `pcscf`, `icscf`, `scscf` and `hss` in the branded realm → `10.90.0.20`, `.21`, `.22` and `.12`, respectively.
- `_sip._udp.<realm>` → `icscf.<realm>:4060`.
- `_sip._udp.pcscf.<realm>` → `pcscf.<realm>:5060`.

My deployed UE client is the direct-Gm registration example from [pro2call](https://github.com/lyatanski/pro2call), source commit `af500940596902679788c396b1931d919253a8ec`, with its image pinned to `ghcr.io/lyatanski/pro2call@sha256:a5ec1f79392a0937b9c339df265b59e2cc13a0793b29e30b0b641d85026c11a8`. It runs beside UERANSIM in the UE pod, bound to `10.46.0.2`; it does not create a replacement access session.

For this already-deployed client, I can repeat the registration-only probe without displaying its protected credential file:

```sh
podman exec dpt-ims-ue-client sh -c '. /run/ims-client.env; export IMS_VERBOSE=0 IMS_DUMP=0; exec lua /opt/ims_test_gm.lua'
```

The private environment requires IMS-AKA/IPsec. The successful run reported one protected registration, REGISTER/200 OK, and clean deregistration. This probe does **not** originate a call or leave a persistent registered phone.

### 6. Roll back if a migration check fails

Stop only the replacement services involved in the failed change. Restore their private startup/environment files and the saved active configuration; do not mix old realm settings with new subscriber identities. Restore the affected I-CSCF route/domain rows and HSS subscriber profile from the verified backup if those were changed.

Only after restoring a consistent configuration should I rename/restart the retained original containers, ensuring that old and new containers do not compete for the same static IP addresses. DNS has its own pre-route backup and retained container. Do not restore an entire database over live newer data merely to undo one routing field; use the full dump as a protected recovery artifact when a full restore is genuinely required.

Never run volume-deleting teardown or replay a full-core manifest as a realm rollback. Recheck DNS, Diameter, secure registration and the internet baseline after recovery.

## What my core overlay proposes

The generated overlay:

1. Keeps the internet session pool and explicitly identifies its DNN.
2. Adds an `ims` session pool and a second UPF TUN interface, `ogstun2`.
3. Adds P-CSCF advertisement and IMS DNS settings to the SMF.
4. Adds SCP/BSF configuration and containers using the existing core image.
5. Adds UPF setup for the separate IMS gateway.

It does **not** attach a second network to the active core, configure subscribers, turn on validated voice support, or apply QoS policies automatically.

The core must be deliberately attached to both its existing network and the IMS bridge before using this overlay. The P-CSCF, DNS and media relay need routes back to the IMS UE pool through the UPF, without address translation that would break subscriber-IP policy correlation or IMS IPsec.

The overlay also changes the SMF's DNS list, so internet DNS must be regression-tested after any future activation. I must validate DNS recursion/forwarding, IMS SRV records, N5/SCP/BSF discovery and Open5GS 2.7.5 compatibility on the real deployment—not assume them from static YAML.

## Subscribers and my test SIM

[`subscriber.template.yaml`](subscriber.template.yaml) records intended identities and QoS targets. It is **not** an API request or an active subscriber record.

The active simulated-UE IMSI is `999050000000001`. A future physical-test-SIM IMSI would be separate; I have not verified a physical handset with this deployment.

Before provisioning, I must match:

- USIM/ISIM identity and authentication material.
- IMS private identity (IMPI), public identities (IMPU) and realm.
- Sequence-number state and authentication algorithm.
- Core and IMS-HSS subscriber records.
- IMS DNN, slice and phone carrier/IMS configuration.

The fresh physical-SIM profile remains private and is not imported or activated by this preparation. I must not substitute the public demonstration authentication values already present in the old simulator examples.

The signaling and conversational-voice QoS classes are **5QI 5 and 5QI 1**. [`qos-policy.json`](qos-policy.json) is a non-secret policy template: its voice flow filters are intentionally empty because actual media flows must come from policy authorization. Provisioned policy is not evidence that a dedicated voice flow was installed, and successful SIP registration alone does not verify QoS or media.

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

## Fresh-deployment activation guardrails

The original VM had 2 GiB RAM; activation later increased it to 6 GiB. The startup guard still rejects insufficient capacity, with a minimum near 4 GiB. A future RAM change requires separately approved downtime.

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

This is a guarded fresh-deployment entry point, **not the in-place realm migration procedure**. It uses the project's pinned Compose provider. Do not execute it merely to make dashboard boxes green.

## Validation and what remains

I validated source pinning/checksums, IMS-only selection, secret-file permissions, archive safety, Compose parsing, generated shell syntax, startup guards, realm consistency and persistent DNS-route setup. Runtime checks verified protected simulated-UE registration, Diameter connectivity, direct IMS UE DNS and the internet tunnel. The separate standalone SIP test verified B2BUA/Telnyx call setup and teardown only.

I have **not** yet verified:

- Correct IMS DNN/PCO behavior with a real phone.
- N5 policy authorization and voice QoS creation/removal.
- A call through UE → IMS CSCFs → B2BUA → Telnyx.
- Bidirectional RTP/audio and the planned 350-Hz test tone.
- Real handset VoNR.

I rerun the automated suite from the repository root:

```bash
.venv/bin/python -m unittest discover -s monitoring -p 'test_*.py' -v
```

A genuine VoNR demonstration requires a compatible 5G SA gNodeB, phone, provisioned test USIM/ISIM and suitable radio test environment. UERANSIM does not become a handset IMS client just because I add these servers. Wi-Fi access alone is not VoNR.

## Recovery and limits

For the active IMS stack, stop only the intended IMS services while preserving the SQL volume. Do not use volume-deleting teardown as a recovery shortcut. Roll back core changes, if ever needed, using the saved original manifest, original network attachment and tested subscriber backup—not by blindly replaying a candidate overlay.

This is a private lab, not a carrier service. A Telnyx trunk has been tested separately; IMS-to-trunk routing is still outstanding. There is no verified SMS service, emergency-calling support, lawful-intercept integration or production availability guarantee.

## Project files

- [`topology.yaml`](topology.yaml) — non-secret addresses and activation gates.
- [`reference.json`](reference.json) — pinned upstream source/hash.
- [`lab.py`](lab.py) — preparation, validation, core overlay and guarded start.
- [`subscriber.template.yaml`](subscriber.template.yaml) — unprovisioned identity/QoS design.
- [`qos-policy.json`](qos-policy.json) — non-secret signaling/voice policy template, not active-flow evidence.
- [`../monitoring/ims_monitor.py`](../monitoring/ims_monitor.py) — read-only inventory collector.
- [`../monitoring/ims.html`](../monitoring/ims.html) — IMS dashboard.

## References and acknowledgements

- [docker_open5gs](https://github.com/herlesupreeth/docker_open5gs) — reference deployment; retain its BSD notices.
- [Kamailio's open-source VoNR demonstration](https://www.kamailio.org/w/2024/04/kamailio-powering-first-live-demo-of-5g-vonr-and-smsonr-with-oss-only/).
- [Open5GS Dockerized VoLTE tutorial](https://open5gs.org/open5gs/docs/tutorial/03-VoLTE-dockerized/) — related IMS background, not proof this VoNR adaptation works.

**What I achieved here:** a running private IMS lab with a consistent branded realm, verified secure simulated-UE registration and working direct IMS DNS, while keeping the remaining call, media and voice-QoS work clearly separate.
