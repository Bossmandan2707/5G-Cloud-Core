import json
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import Mock, patch

import dashboard


class ContainerSamplingTests(unittest.TestCase):
    def sample_once(self, stats):
        with patch.dict(dashboard.STATE, {"containers": [], "container_error": None}), patch("dashboard.PODMAN", "/podman"):
            with patch("dashboard.run_podman", side_effect=["ue-ue\texited\tExited (0)", stats]):
                with patch("dashboard.time.sleep", side_effect=StopIteration):
                    with self.assertRaises(StopIteration):
                        dashboard.sample_containers()
            return dashboard.STATE["containers"], dashboard.STATE["container_error"]

    def test_null_stats_when_no_containers_running(self):
        rows, error = self.sample_once("null")
        self.assertIsNone(error)
        self.assertEqual(rows[0]["name"], "ue-ue")
        self.assertIsNone(rows[0]["cpu"])

    def test_malformed_stats_reports_error_without_crashing_sampler(self):
        for stats in ('{"error": "unavailable"}', '["invalid"]', '{}', 'false', '0'):
            rows, error = self.sample_once(stats)
            self.assertEqual(rows, [])
            self.assertIn("unavailable", error)


class HostSamplingTests(unittest.TestCase):
    def test_exporter_returns_same_cpu_value_it_exposes(self):
        with patch.object(dashboard.exporter.psutil, "cpu_percent", return_value=25.5):
            with patch.object(dashboard.exporter.psutil, "virtual_memory", return_value=Mock(percent=42)):
                with patch.object(dashboard.exporter.psutil, "disk_usage", return_value=Mock(percent=60)):
                    with patch.object(dashboard.exporter.os, "getloadavg", return_value=(1, 2, 3)):
                        with patch.object(dashboard.exporter, "TARGETS", []):
                            self.assertEqual(dashboard.exporter.collect(), 25.5)
        self.assertIn(b"host_cpu_percent 25.5", dashboard.generate_latest())


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), dashboard.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_html(self):
        with urllib.request.urlopen(self.base + "/") as response:
            html = response.read()
            self.assertIn(b"<title>Dan Powell Technologies", html)
            self.assertIn(b"<h1>Dan Powell Technologies</h1>", html)
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_mdm_page(self):
        with urllib.request.urlopen(self.base + "/mdm") as response:
            html = response.read()
            self.assertIn(b"UE MDM", html)
            self.assertIn(b"AGENT HEARTBEAT", html)
            self.assertIn(b"read-only", html)

    def test_mdm_api_and_metrics(self):
        with urllib.request.urlopen(self.base + "/api/mdm") as response:
            data = json.load(response)
            self.assertIn("agent_fresh", data)
            self.assertIn("native_fresh", data)
            self.assertIn("history", data)
        with urllib.request.urlopen(self.base + "/metrics") as response:
            self.assertIn(b"ue_mdm_agent_up", response.read())

    def test_interfaces_page(self):
        with urllib.request.urlopen(self.base + "/interfaces") as response:
            html = response.read()
            self.assertIn(b"Dan Powell Technologies", html)
            self.assertIn(b"N-interface topology", html)
            self.assertIn(b'aria-current="page">Interfaces', html)

    def test_interfaces_api(self):
        with urllib.request.urlopen(self.base + "/api/interfaces") as response:
            data = json.load(response)
            self.assertIn("links", data)
            self.assertIn("endpoints", data)
            self.assertIn("stale", data)
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_snapshot(self):
        with urllib.request.urlopen(self.base + "/api/snapshot") as response:
            snapshot = json.load(response)
            self.assertIn("host", snapshot)
            self.assertEqual(snapshot["lab_name"], "Dan Powell Technologies")
            self.assertIsInstance(snapshot["containers"], list)
            self.assertEqual(response.headers["Content-Type"], "application/json")

    def test_ims_page_and_readiness_api(self):
        with urllib.request.urlopen(self.base + "/ims") as response:
            html = response.read()
            self.assertIn(b"VoNR acceptance gates", html)
            self.assertIn(b'id="network-map"', html)
            self.assertIn(b"Telnix Los Angeles Interconnect", html)
            self.assertIn(b"no arm, dial or call controls", html)
            self.assertIn(b'id="ue-sip-ladder"', html)
            self.assertNotIn(b"map-gated", html)
            self.assertNotIn(b"M672 427L683", html)
        with urllib.request.urlopen(self.base + "/api/ims") as response:
            data = json.load(response)
            self.assertIn("verification", data)
            self.assertIn("services", data)
            self.assertIn("network_map", data)
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_metrics(self):
        with urllib.request.urlopen(self.base + "/metrics") as response:
            metrics = response.read()
            self.assertIn(b"host_cpu_percent", metrics)
            self.assertIn(b'lab_info{name="Dan Powell Technologies"} 1.0', metrics)

    def test_no_file_access(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(self.base + "/../.git/config")
        self.assertEqual(error.exception.code, 404)

    def test_dashboard_alias(self):
        with urllib.request.urlopen(self.base + "/dashboard") as response:
            self.assertEqual(response.status, 200)

    def test_gtp_page(self):
        with urllib.request.urlopen(self.base + "/gtp") as response:
            html = response.read()
            self.assertIn(b"Dan Powell Technologies", html)
            self.assertIn(b"Real-time packet trace", html)

    def test_gtp_snapshot(self):
        with urllib.request.urlopen(self.base + "/api/gtp") as response:
            data = json.load(response)
            self.assertIsInstance(data["packets"], list)
            self.assertEqual(data["buffer_limit"], 500)
            self.assertIn("UL", data["rates"])
            self.assertIn("DL", data["rates"])
            self.assertEqual(response.headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()
