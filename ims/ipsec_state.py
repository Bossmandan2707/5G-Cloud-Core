"""Inspect only ESP endpoint/SPI metadata, never auth or encryption key fields."""
import re


def associations(text):
    rows = []
    current = None
    for line in text.splitlines():
        match = re.match(r"^src (\S+) dst (\S+)", line)
        if match:
            current = {"src": match.group(1), "dst": match.group(2)}
            rows.append(current)
        elif current is not None:
            match = re.match(r"\s*proto esp spi (0x[0-9a-fA-F]+) reqid (\d+) mode (\w+)", line)
            if match:
                current.update(spi=int(match.group(1), 16),
                               reqid=int(match.group(2)), mode=match.group(3))
    return [row for row in rows if "spi" in row]


def peer_health(agent, pcscf_address, ue, pcscf):
    address = agent.get("address")
    specifications = (
        ("UE client -> P-CSCF server", address, pcscf_address, agent.get("pcscf_server_spi")),
        ("UE server -> P-CSCF client", address, pcscf_address, agent.get("pcscf_client_spi")),
        ("P-CSCF server -> UE client", pcscf_address, address, agent.get("ue_client_spi")),
        ("P-CSCF client -> UE server", pcscf_address, address, agent.get("ue_server_spi")),
    )
    missing = []
    for label, source, destination, spi in specifications:
        if not source or not destination or type(spi) is not int:
            return {"verified": False, "scope": "Negotiated SPI metadata not available",
                    "missing": []}
        for side, rows in (("UE", ue), ("P-CSCF", pcscf)):
            if not any(row["src"] == source and row["dst"] == destination
                       and row["spi"] == spi and row.get("mode") == "transport"
                       for row in rows):
                missing.append({"side": side, "association": label, "spi": hex(spi)})
    return {"verified": not missing, "missing": missing,
            "scope": "Endpoint/SPI installation check, not key disclosure or full call verification"}
