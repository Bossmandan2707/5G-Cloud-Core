import copy
import json
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

import mdm
from telemetry.ue_mdm import agent


def sample(now=100):
    return {"schema_version": 1, "status": "ok", "configured_imsi": "999050000000001",
            "collected_at": now, "sample_age_seconds": 1, "uptime_seconds": 100,
            "interfaces": [{"name": "uesimtun0", "admin_up": True, "addresses": ["10.45.0.2"],
                            "counters": {"rx_bytes": 100, "tx_bytes": 50},
                            "rates": {"rx_bps": 10, "tx_bps": 5, "counter_reset": False}}],
            "tunnel": {"name": "uesimtun0", "ip": "10.45.0.2", "admin_up": True},
            "probe": {"up": True, "checked_at": now, "route_verified": True, "latency_ms": 4},
            "agent_resources": {"cpu_percent": .1, "rss_bytes": 1024},
            "routes": [], "rules": []}


class AgentTests(unittest.TestCase):
    def test_counter_rates_and_reset(self):
        self.assertIsNone(agent.counter_rates({"rx_bytes": 1, "tx_bytes": 2}, None, 1)["rx_bps"])
        self.assertEqual(agent.counter_rates({"rx_bytes": 30, "tx_bytes": 20}, {"rx_bytes": 10, "tx_bytes": 10}, 2)["rx_bps"], 10)
        reset = agent.counter_rates({"rx_bytes": 1, "tx_bytes": 2}, {"rx_bytes": 30, "tx_bytes": 20}, 2)
        self.assertTrue(reset["counter_reset"])
        self.assertIsNone(reset["rx_bps"])

    @patch("telemetry.ue_mdm.agent.socket.create_connection")
    @patch("telemetry.ue_mdm.agent.read_ip", return_value=[{"dev": "eth0"}])
    def test_probe_never_falls_back_to_pod_uplink(self, read_ip, connect):
        value = agent.bound_probe("10.45.0.2", "uesimtun0")
        self.assertIsNone(value["up"])
        self.assertFalse(value["route_verified"])
        connect.assert_not_called()

    @patch("telemetry.ue_mdm.agent.socket.create_connection")
    @patch("telemetry.ue_mdm.agent.read_ip", return_value=[{"dev": "uesimtun0"}])
    def test_probe_binds_verified_tunnel_ip(self, read_ip, connect):
        connect.return_value.__enter__.return_value.getsockname.return_value = ("10.45.0.2", 12345)
        result = agent.bound_probe("10.45.0.2", "uesimtun0")
        self.assertTrue(result["up"])
        self.assertEqual(connect.call_args.kwargs["source_address"], ("10.45.0.2", 0))
        self.assertEqual(connect.call_args.kwargs["timeout"], 3)

    def test_agent_stale_heartbeat(self):
        value = agent.Agent()
        value.data = sample()
        value.last_sample = time.monotonic() - 25
        self.assertEqual(value.snapshot()["status"], "stale")

    def test_agent_metrics_do_not_claim_ue_cpu(self):
        text = agent.metrics(sample()).decode()
        self.assertIn("ue_mdm_agent_cpu_percent", text)
        self.assertNotIn("ue_mdm_ue_cpu_percent", text)

    def test_network_metadata_whitelist(self):
        value = agent.safe_network_metadata([{"dst": "default", "secret": "sentinel"}], ("dst",))
        self.assertEqual(value, [{"dst": "default"}])

    def test_agent_http_read_only_routes(self):
        value = agent.Agent()
        value.data = sample(time.time())
        value.last_sample = time.monotonic()
        server = ThreadingHTTPServer(("127.0.0.1", 0), agent.make_handler(value))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:" + str(server.server_port)
        try:
            for path in ("/healthz", "/telemetry", "/metrics"):
                with urllib.request.urlopen(base + path) as response:
                    self.assertEqual(response.status, 200)
            with self.assertRaises(urllib.error.HTTPError):
                urllib.request.urlopen(base + "/etc/passwd")
            request = urllib.request.Request(base + "/telemetry", method="POST", data=b"")
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request)
            self.assertEqual(error.exception.code, 501)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


class CollectorTests(unittest.TestCase):
    def monitor(self):
        monitor = mdm.MdmMonitor(None)
        monitor.data = {"updated": 100, "agent": mdm.clean_agent(sample()), "radio_updated": 100,
                        "radio": {"rm-state": "RM-REGISTERED", "cm-state": "CM-IDLE"},
                        "sessions": [{"state": "PS-ACTIVE"}], "resources": {"cpu_percent": .3},
                        "errors": [], "identity": {"imsi": "999050000000001"}}
        return monitor

    def test_native_status_strips_private_identifiers(self):
        value = mdm.native_status("rm-state: RM-REGISTERED\nstored-suci: sentinel\nstored-guti:\n  tmsi: 123\nsim-inserted: true\n")
        self.assertEqual(value, {"rm-state": "RM-REGISTERED", "sim-inserted": True})

    def test_native_session_whitelist(self):
        value = mdm.native_sessions("PDU Session1:\n  state: PS-ACTIVE\n  address: 10.45.0.2\n  apn: internet\n  secret: sentinel\n")
        self.assertEqual(value[0]["id"], 1)
        self.assertNotIn("secret", value[0])

    def test_agent_whitelist_and_invalid_ip(self):
        value = sample()
        value["secret"] = "sentinel"
        value["interfaces"][0]["addresses"].append("invalid")
        result = mdm.clean_agent(value)
        self.assertNotIn("secret", result)
        self.assertEqual(result["interfaces"][0]["addresses"], ["10.45.0.2"])

    def test_nonfinite_value_is_not_exposed(self):
        value = sample()
        value["agent_resources"]["cpu_percent"] = float("nan")
        json.dumps(mdm.clean_agent(value), allow_nan=False)

    def test_fresh_native_state_and_agent(self):
        value = self.monitor().snapshot(now=105)
        self.assertTrue(value["agent_fresh"])
        self.assertTrue(value["native_fresh"])
        self.assertTrue(value["probe_fresh"])
        self.assertEqual(value["warnings"], [])

    def test_stale_does_not_report_live(self):
        value = self.monitor().snapshot(now=140)
        self.assertTrue(value["stale"])
        self.assertFalse(value["agent_fresh"])
        self.assertFalse(value["native_fresh"])

    def test_missing_agent_is_distinct_from_native_state(self):
        monitor = self.monitor()
        monitor.data["agent"] = None
        value = monitor.snapshot(now=105)
        self.assertFalse(value["agent_fresh"])
        self.assertTrue(value["native_fresh"])

    def test_history_is_bounded(self):
        monitor = self.monitor()
        for i in range(130):
            monitor.history.append({"at": i})
        self.assertEqual(len(monitor.snapshot(now=105)["history"]), 120)

    @patch("mdm.time.time", return_value=105)
    def test_metrics_have_separate_ue_and_agent_cpu(self, clock):
        text = self.monitor().render_metrics().decode()
        self.assertIn("ue_mdm_registered 1.0", text)
        self.assertIn("ue_mdm_ue_cpu_percent 0.3", text)
        self.assertIn("ue_mdm_agent_cpu_percent 0.1", text)

    @patch("mdm.time.time", return_value=140)
    def test_stale_metrics_omit_cached_positive_states(self, clock):
        text = self.monitor().render_metrics().decode()
        self.assertIn("ue_mdm_agent_up 0.0", text)
        self.assertNotIn("ue_mdm_registered", text)


if __name__ == "__main__":
    unittest.main()
