# Roaming partner preparation

These are **inactive technical planning profiles**, not signed roaming agreements, deployed Open5GS configuration or evidence of operator connectivity.

No runtime component loads these files. They are not inputs to `podman kube play`, Open5GS or freeDiameter. Flipping an `enabled` value does not create an interconnect or authorize subscribers.

## Three UK — inbound S8 home routing

[`partners/three-uk.yaml`](partners/three-uk.yaml) describes **Three UK subscribers visiting the Dan Powell Technologies lab**:

- Home network: Three UK, primary PLMN **234/20**.
- Allocation holder in the Ofcom register: **Hutchison 3G UK Ltd**.
- Visited network: the existing lab PLMN **999/05**, unchanged.
- Architecture: **LTE/EPC S8HR**, not 5G SA roaming.
- State: **draft-inactive**, with no established agreement or confirmed operator parameters.
- Scope: IMSI identification, S8-C/S8-U placeholders and S6a Diameter realm/peer placeholders. **No SEPP** is included.

The primary network identity was checked against [Ofcom's MNC allocation register](https://www.ofcom.org.uk/siteassets/resources/documents/phones-telecoms-and-internet/information-for-industry/numbering/regular-updates/codes/mnc.csv?v=426913) on 11 November 2026. Ofcom also lists **235/94** for Hutchison 3G UK. That allocation is recorded as reference-only and is **not included** in this profile's IMSI or routing scope. Neither an allocation nor common ownership establishes roaming authorization for other PLMNs, hosted MVNOs or brands.

### IMSI series versus subscriber authorization

The primary prefix is **`23420`**, preserving the two-digit MNC `20`.

For a 15-digit IMSI, the identification envelope is **`234200000000000`–`234209999999999`**. This only describes numbers matching the prefix and length; it is not a claim that the entire envelope is issued, eligible or approved for roaming.

`operator_authorized_ranges` is deliberately empty. The planning policy is deny-until-operator-approved. No subscriber records, SIM authentication keys or admission rules are imported or changed. Actual subscriber authentication and subscription data remain the home network's responsibility.

### S8 interfaces

- **S8-C:** visited **SGW-C → home PGW-C**, using GTPv2-C over UDP **2123**, with bidirectional control signaling.
- **S8-U:** visited **SGW-U ↔ home PGW-U**, using GTP-U over UDP **2152**.

All local bind/advertised addresses, remote addresses, approved APNs and home-PGW selection parameters remain unset. DNS resolution or static PGW selection must be agreed and validated against the deployed EPC release, not assumed.

No routes or firewall openings are installed. The interconnect interface, peer networks, security, routing and firewall policies are also unset. Do not expose GTP or Diameter to the public internet as a shortcut.

### Diameter realms

S6a connects the visited MME to the home HSS through the agreed direct or DRA/DEA peer arrangement:

- Application ID: **16777251**, 3GPP vendor ID **10415**.
- Candidate home realm: **`epc.mnc020.mcc234.3gppnetwork.org`**.
- Candidate visited realm: **`epc.mnc005.mcc999.3gppnetwork.org`**.

These strings are derived from PLMN formatting, including three-digit MNC padding in domain names. They are **not verified deployed Diameter realms or peer identities**.

The operational `origin_realm` and `destination_realm` fields remain null, as do Origin-Host, Destination-Host, peer identity/address/port, transport and security policy. Peer connection and unknown-peer acceptance are disabled; there are no realm routes or catch-all rules. No peer hostname, certificate or security relationship is fabricated.

The existing local Kamailio/PyHSS IMS realm and Cx connections are untouched. In genuine S8HR, IMS service remains home-routed according to the operator's approved design; this profile does not redirect Three UK subscribers into the lab's local IMS service.

## What is needed before activation

The current deployment provides 5G SA AMF/SMF/UPF functions and an NR simulator. It does **not** currently deploy the visited LTE/EPC MME, SGW-C and SGW-U required by this design. Existing GTP listeners in the 5G core are not evidence of an active S8HR service, and UERANSIM is not an LTE eNodeB.

Activation is a separate reviewed task requiring:

1. An actual operator-approved roaming arrangement and permitted IMSI subranges, PLMNs and services.
2. Approved APNs and home-PGW selection/endpoints.
3. Agreed S6a realms, Diameter identities, peers and transport/security parameters.
4. A secure interconnect, addressing, routing, MTU and firewall policies.
5. A separately reviewed visited EPC deployment and suitable LTE access/test equipment.
6. Controlled attach, authentication, bearer, S8 forwarding and teardown tests; IMS/media and charging validation where applicable.

Do not change the active lab PLMN, copy foreign subscriber secrets into the lab, restart the working core, or treat this planning profile as permission to connect to Three UK.

## Offline validation

The profile's consistency and inactive defaults are covered by `monitoring/test_roaming.py` in the existing suite:

```bash
.venv/bin/python -m unittest discover -s monitoring -p 'test_*.py'
```

These tests validate planning data only. They do not contact the operator or demonstrate roaming interoperability.

## Architecture references

- [Open5GS EPC/5GC architecture and component roles](https://open5gs.org/open5gs/docs/guide/01-quickstart/).
- [Open5GS interface diagram](https://open5gs.org/open5gs/assets/Open5GS-Diagram.pdf), including S5/S8-C, S5/S8-U and S6a.
