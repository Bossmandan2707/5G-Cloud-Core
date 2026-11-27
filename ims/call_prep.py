"""Render a restricted test gateway; never embed trunk credentials or dial."""
import ipaddress
import json
import re
from pathlib import Path


def validate_profile(profile):
    result = dict(profile)
    for field in ("destination", "external_caller_id"):
        if not isinstance(result.get(field), str) or not re.fullmatch(
                r"\+[1-9][0-9]{7,14}", result[field]):
            raise ValueError(f"{field} must be an E.164 number")
    for field, maximum in (("ring_timeout_seconds", 15), ("maximum_answered_seconds", 5)):
        value = result.get(field, maximum)
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError(f"{field} must be between 1 and {maximum}")
        result[field] = value
    if result.get("automatic_dial", False) is not False:
        raise ValueError("Automatic dialing must remain disabled")
    result["automatic_dial"] = False
    if "caller_display_name" in result:
        if not isinstance(result["caller_display_name"], str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}", result["caller_display_name"]):
            raise ValueError("caller_display_name contains unsupported characters")
    if "connection_username" in result:
        if not isinstance(result["connection_username"], str) or not re.fullmatch(
                r"[A-Za-z0-9_.+\-]{1,128}", result["connection_username"]):
            raise ValueError("connection_username contains unsupported characters")
    return result


def load_profile(path):
    return validate_profile(json.loads(Path(path).read_text()))


def gateway_configuration(profile, gateway="10.90.0.24", scscf="10.90.0.22"):
    profile = validate_profile(profile)
    gateway = str(ipaddress.IPv4Address(gateway))
    scscf = str(ipaddress.IPv4Address(scscf))
    caller = profile["external_caller_id"]
    destination = profile["destination"]
    display_name = profile.get("caller_display_name", "Dan Powell Lab")
    contact_user = ("contact_user=" + profile["connection_username"] + "\n"
                    if profile.get("connection_username") else "")
    pjsip = f"""[global]
type=global
user_agent=DanPowellLab-IMS-B2BUA
endpoint_identifier_order=ip
[ims-udp]
type=transport
protocol=udp
bind={gateway}:5060
[provider-tls]
type=transport
protocol=tls
bind=0.0.0.0:5063
method=tlsv1_2
verify_server=yes
ca_list_file=/etc/ssl/certs/ca-certificates.crt
[ims]
type=endpoint
transport=ims-udp
context=ims-outbound
identify_by=ip
disallow=all
allow=ulaw
allow=alaw
direct_media=no
[ims-identify]
type=identify
endpoint=ims
match={scscf}/32
[telnyx]
type=endpoint
transport=provider-tls
context=reject-inbound
identify_by=ip
disallow=all
allow=ulaw
allow=alaw
outbound_auth=telnyx-auth
aors=telnyx-address
from_user={caller}
from_domain=sip.telnyx.eu
{contact_user}send_pai=yes
callerid={display_name} <{caller}>
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
[telnyx-address]
type=aor
contact=sip:sip.telnyx.eu:5061;transport=tls
#include dpt-trunk-auth.conf
"""
    dialplan = f"""[general]
static=yes
writeprotect=yes
[globals]
DPT_OUTBOUND_ARMED=0
[ims-outbound]
exten => {destination},1,NoOp(DPT_IMS_INGRESS)
 same => n,Set(DPT_LOCK=${{TRYLOCK(dpt-outbound-gate)}})
 same => n,GotoIf($["${{DPT_LOCK}}" != "1"]?preflight)
 same => n,GotoIf($["${{GLOBAL(DPT_OUTBOUND_ARMED)}}" = "1"]?authorized)
 same => n,Set(DPT_UNLOCK=${{UNLOCK(dpt-outbound-gate)}})
 same => n(preflight),NoOp(DPT_PREFLIGHT_BLOCKED)
 same => n,Hangup(21)
 same => n(authorized),Set(GLOBAL(DPT_OUTBOUND_ARMED)=0)
 same => n,Set(DPT_UNLOCK=${{UNLOCK(dpt-outbound-gate)}})
 same => n,Set(CALLERID(num)={caller})
 same => n,Set(CALLERID(name)={display_name})
 same => n,Set(TIMEOUT(absolute)=25)
 same => n,Dial(PJSIP/{destination}@telnyx,{profile["ring_timeout_seconds"]},L({profile["maximum_answered_seconds"] * 1000}))
 same => n,Hangup()
exten => _X.,1,Hangup(21)
exten => _+X.,1,Hangup(21)
exten => h,1,NoOp(DPT_IMS_RESULT status=${{DIALSTATUS}} cause=${{HANGUPCAUSE}})
[reject-inbound]
exten => _X.,1,Hangup(21)
exten => _+X.,1,Hangup(21)
"""
    return {"pjsip.conf": pjsip, "extensions.conf": dialplan}
