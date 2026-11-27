import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import interfaces


EPS = "ENDPT SOCK STY SST HBKT LPORT UID INODE LADDRS\nx x 2 10 16 38412 999 18689 127.0.0.5\n"
ASSOCS = ("ASSOC SOCK STY SST ST HBKT ASSOC-ID TX_QUEUE RX_QUEUE UID INODE LPORT RPORT LADDRS <-> RADDRS\n"
          "x x 2 1 3 0 3 0 0 0 16905 43563 38412 127.0.0.1 <-> *127.0.0.5 30000\n")


def namespace(addresses, sockets=""):
    return interfaces.parse_namespace(
        "__ADDR__\n" + json.dumps(addresses) + "\n__ROUTES__\n"
        '[{"dst":"default","gateway":"10.89.0.1","dev":"eth0"}]\n'
        "__SOCKETS__\n" + sockets + "\n__EPS__\n" + EPS +
        "__ASSOCS__\n" + ASSOCS + "__FORWARD__\n1\n__NAT__\n"
        "-A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE\n")


def netdev(name, address, prefix=24, state="UP", up=True):
    return {"ifname": name, "operstate": state, "flags": ["UP"] if up else [],
            "addr_info": [{"family": "inet", "local": address, "prefixlen": prefix}]}


class ParsingTests(unittest.TestCase):
    def test_ipv4_ipv6_socket_parsing(self):
        rows = interfaces.parse_sockets(
            "tcp LISTEN 0 5 127.0.0.5:7777 0.0.0.0:*\n"
            "udp UNCONN 0 0 [::1]:2152 [::]:*\n")
        self.assertEqual(rows[0]["port"], 7777)
        self.assertEqual(rows[1]["address"], "::1")

    def test_sctp_association_and_listener(self):
        self.assertEqual(interfaces.parse_sctp(EPS)[0]["address"], "127.0.0.5")
        row = interfaces.parse_sctp(ASSOCS, True)[0]
        self.assertEqual(row["state"], 3)
        self.assertEqual(row["remote"], "127.0.0.5")
        self.assertEqual(row["local_port"], 43563)

    def test_unknown_tun_is_admin_up(self):
        data = namespace([netdev("uesimtun0", "10.45.0.9", 32, "UNKNOWN")])
        self.assertTrue(data["devices"][0]["admin_up"])
        self.assertEqual(data["devices"][0]["kernel_state"], "UNKNOWN")

    def test_socket_failure_is_not_reported_available(self):
        self.assertFalse(namespace([], "unavailable")["sockets_available"])

    def test_missing_configmap_is_clear_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "invalid.yaml"
            path.write_text("kind: Pod\nmetadata:\n  name: test\n")
            with self.assertRaises(ValueError):
                interfaces.load_layout(path)

    def test_layout_exposes_only_network_metadata(self):
        allowed = {"id", "component", "service", "address", "port", "protocol", "container", "source"}
        for row in interfaces.load_layout():
            self.assertEqual(set(row), allowed)
        self.assertEqual({r["component"] for r in interfaces.load_layout()},
                         {"NRF", "AMF", "SMF", "UPF", "AUSF", "UDM", "UDR", "PCF", "gNB", "MongoDB"})


class MappingTests(unittest.TestCase):
    def setUp(self):
        self.layout = interfaces.load_layout()
        sockets = "\n".join(
            f'{e["protocol"]} {"LISTEN" if e["protocol"]=="tcp" else "UNCONN"} 0 0 {e["address"]}:{e["port"]} 0.0.0.0:*'
            for e in self.layout if e["address"] and e["protocol"] != "sctp")
        sockets += "\nudp UNCONN 0 0 10.89.0.50:4997 0.0.0.0:*\n"
        self.core = namespace([netdev("eth0", "10.89.0.50"), netdev("ogstun", "10.45.0.1", 16, "UNKNOWN")], sockets)
        self.ue = namespace([netdev("eth0", "10.89.0.7"), netdev("uesimtun0", "10.45.0.9", 32, "UNKNOWN")])
        self.namespaces = {"core": self.core, "ue": self.ue,
                           "vm": namespace([netdev("eth0", "192.168.127.2")]),
                           "host": namespace([netdev("en0", "192.168.1.70")])}
        self.states = {e["container"]: "running" for e in self.layout}

    def build(self):
        return interfaces.build_map(self.layout, self.namespaces, self.states, now=100)

    def test_all_lab_n_interfaces_present(self):
        names = {row["name"] for row in self.build()["links"]}
        self.assertTrue({"N1", "N2", "N3", "N4", "N6", "N7", "N8", "N10",
                         "N11", "N12", "N13", "N15", "N35"}.issubset(names))

    def test_dynamic_ue_address_and_live_sctp(self):
        data = self.build()
        self.assertEqual(next(n for n in data["nodes"] if n["name"] == "UE")["address"], "10.45.0.9/32")
        links = {row["name"]: row for row in data["links"]}
        self.assertEqual(links["N1"]["status"], "logical")
        self.assertIsNone(links["N1"]["right"]["port"])
        self.assertEqual(links["N2"]["status"], "established")
        self.assertEqual(links["N3"]["status"], "endpoints observed")
        self.assertEqual(links["UE tunnel"]["status"], "interfaces up")
        self.assertEqual(links["N6"]["status"], "routing ready")
        self.assertEqual(links["N6"]["right"]["address"], "10.89.0.1")

    def test_radio_uses_live_address_not_config_loopback(self):
        radio = next(e for e in self.build()["endpoints"] if e["service"] == "radio")
        self.assertEqual(radio["address"], "10.89.0.50")
        self.assertEqual(radio["source"], "live socket")

    def test_stopped_container_is_not_green(self):
        self.states["open5gs-smf"] = "exited"
        data = self.build()
        self.assertEqual(next(l for l in data["links"] if l["name"] == "N4")["status"], "down")

    def test_failed_namespace_does_not_reuse_green_state(self):
        self.namespaces["core"] = interfaces.unknown_namespace("Stopped")
        data = self.build()
        self.assertTrue(all(e["status"] == "unknown" for e in data["endpoints"]))
        self.assertEqual(next(l for l in data["links"] if l["name"] == "N2")["status"], "unknown")

    def test_unrelated_nat_rule_does_not_mark_n6_ready(self):
        self.core["nat_sources"] = ["192.168.0.0/16"]
        self.assertEqual(next(l for l in self.build()["links"] if l["name"] == "N6")["status"], "unknown")

    def test_sctp_listener_without_association_is_not_established(self):
        self.core["associations"] = []
        self.assertEqual(next(l for l in self.build()["links"] if l["name"] == "N2")["status"], "listening")

    def test_stale_monitor_invalidates_all_statuses(self):
        monitor = interfaces.InterfaceMonitor(None)
        monitor.data = self.build()
        stale = monitor.snapshot(now=146)
        self.assertTrue(stale["stale"])
        self.assertTrue(all(e["status"] == "stale" for e in stale["endpoints"]))
        self.assertEqual(monitor.data["nodes"], self.build()["nodes"])

    @patch("interfaces.subprocess.run")
    def test_missing_podman_returns_unknown_without_a_command(self, run):
        data = interfaces.InterfaceMonitor(None).namespace("core")
        self.assertIsNotNone(data["error"])
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
