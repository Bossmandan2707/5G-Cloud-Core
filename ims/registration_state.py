"""Public registration evidence only; no credentials, vectors or digest headers."""
import json
import re
import time
from pathlib import Path


def sessions(text):
    result = {}
    for section in re.split(r"PDU Session\d+:", text)[1:]:
        fields = dict(re.findall(r"^\s*(state|apn|address):\s*([^\r\n]+)", section, re.M))
        if fields.get("apn"):
            result[fields["apn"].strip()] = {
                key: fields.get(key, "").strip() for key in ("state", "address")}
    return result


def scscf_contact(text, impu):
    if not text.strip():
        return {"queried": True, "registered": False, "contacts": []}
    identity = re.search(r"^\s*impu:\s*(\S+)\s*$", text, re.M)
    state = re.search(r"^\s*state:\s*(\S+)\s*$", text, re.M)
    if not identity or identity.group(1) != impu or not state:
        return {"queried": False, "registered": None, "contacts": []}
    contact_text = text.split("contacts:", 1)[-1] if "contacts:" in text else ""
    contacts = []
    for uri, body in re.findall(r"^\s*(sip:\S+):\s*\{([^{}]*)\}", contact_text, re.M):
        expiry = re.search(r"^\s*expires:\s*(-?\d+)\s*$", body, re.M)
        if expiry:
            contacts.append({"uri": uri, "expires_in": int(expiry.group(1))})
    registered = state.group(1).lower() == "registered" and any(
        c["expires_in"] > 0 for c in contacts)
    return {"queried": True, "registered": registered,
            "state": state.group(1), "impu": impu, "contacts": contacts}


def agent_status(path, now=None):
    now = time.time() if now is None else now
    try:
        path = Path(path)
        if path.stat().st_size > 16384:
            raise ValueError("Oversized status")
        value = json.loads(path.read_text())
        fields = ("state", "registered", "imsi", "msisdn", "realm", "address",
                  "renewals", "updated_at", "expires_at", "last_registered_at",
                  "next_renewal_at", "msisdn_associated", "protected", "service_routes",
                  "pcscf_server_spi", "pcscf_client_spi", "pcscf_server_port",
                  "pcscf_client_port", "ue_client_spi", "ue_server_spi")
        result = {key: value.get(key) for key in fields}
        updated, expires = float(result["updated_at"]), float(result["expires_at"])
        result["heartbeat_age_seconds"] = now - updated
        result["status_file_age_seconds"] = time.time() - path.stat().st_mtime
        result["fresh"] = (-3 <= result["heartbeat_age_seconds"] <= 12
                           and -3 <= result["status_file_age_seconds"] <= 12)
        result["lease_valid"] = expires > now
        result["registration_observed"] = (
            result["fresh"] and result["lease_valid"] and result["registered"] is True
            and result["protected"] is True and result["msisdn_associated"] is True)
        return result
    except (OSError, ValueError, TypeError, AttributeError):
        return {"state": "unavailable", "fresh": False,
                "registration_observed": False, "lease_valid": False}
