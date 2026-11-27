import argparse
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml

from ngap_cli import duration, main
from ngap_trace import NgapBuffer, NgapCapture, association_summary, load_layout, parse_packet


DL = ("1795160801.403433 00:00:00:00:00:00 > 00:00:00:00:00:00, IPv4, length 106: "
      "127.0.0.5.38412 > 127.0.0.1.39645: sctp [|sctp]")
UL = DL.replace("127.0.0.5.38412 > 127.0.0.1.39645",
                "127.0.0.1.39645 > 127.0.0.5.38412")
LAYOUT = [
    {"component": "AMF", "service": "ngap", "address": "127.0.0.5", "port": 38412},
    {"component": "gNB", "service": "ngap", "address": "127.0.0.1"},
]


class PacketTests(unittest.TestCase):
    def test_gnb_signaling_bind_is_not_its_gtpu_bind(self):
        config = {"amf.yaml": yaml.safe_dump({"amf": {"ngap": {"server": [{"address": "127.0.0.5"}]}}}),
                  "gnb.yaml": yaml.safe_dump({"ngapIp": "127.0.0.2", "gtpIp": "127.0.0.1"})}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "core.yaml"
            path.write_text(yaml.safe_dump({"kind": "ConfigMap",
                                           "metadata": {"name": "open5gs-config"}, "data": config}))
            layout = load_layout(path)
        self.assertEqual(layout[1]["address"], "127.0.0.2")
        self.assertEqual(layout[0]["port"], 38412)

    def test_actual_tcpdump_summaries_and_no_chunk_text(self):
        for line, direction in ((UL, "UL"), (DL, "DL")):
            packet = parse_packet(line)
            self.assertEqual(packet["direction"], direction)
            self.assertEqual(packet["bytes"], 106)
            self.assertEqual(set(packet), {"timestamp", "source", "source_port",
                                          "destination", "destination_port", "bytes", "direction"})

    def test_other_endpoints_not_misattributed(self):
        self.assertEqual(parse_packet(UL.replace("127.0.0.1", "127.0.0.9"))["direction"], "OTHER")

    def test_ignore_invalid_or_unrelated_lines(self):
        for line in ("listening on lo", "garbage", UL.replace("38412", "2152"),
                     UL.replace("127.0.0.1", "999.0.0.1"), UL.replace("39645", "99999"),
                     UL.replace("length 106", "length 1"), UL.replace("sctp", "UDP"),
                     UL.replace("1795160801.403433", "9" * 400 + ".1")):
            with self.subTest(line=line[:100]):
                self.assertIsNone(parse_packet(line))

    def test_custom_configured_endpoint(self):
        line = UL.replace("127.0.0.5", "127.0.0.8").replace("38412", "38413")
        self.assertIsNone(parse_packet(line))
        self.assertEqual(parse_packet(line, amf="127.0.0.8", port=38413)["direction"], "UL")


class BufferTests(unittest.TestCase):
    def test_bounded_buffer_and_cumulative_totals(self):
        buffer = NgapBuffer(limit=2)
        for _ in range(5):
            buffer.add(parse_packet(UL), now=100)
        data = buffer.snapshot(now=100)
        self.assertEqual([p["id"] for p in data["packets"]], [4, 5])
        self.assertEqual(data["totals"]["UL_packets"], 5)
        self.assertEqual(data["totals"]["UL_bytes"], 530)
        self.assertEqual(data["rates"]["UL"]["pps"], 1)
        self.assertEqual(data["history"][-1]["UL"], 5)
        self.assertEqual(len(data["history"]), 60)
        self.assertNotIn("ue_identity", data)
        self.assertIn("not decoded NGAP", data["scope"])

    def test_idle_expiry_and_snapshot_isolation(self):
        buffer = NgapBuffer()
        buffer.configure("127.0.0.5", "127.0.0.1", 38412)
        buffer.add(parse_packet(DL), now=100)
        data = buffer.snapshot(now=100)
        data["packets"][0]["bytes"] = 0
        data["endpoints"]["amf"] = "wrong"
        fresh = buffer.snapshot(now=100)
        self.assertEqual(fresh["packets"][0]["bytes"], 106)
        self.assertEqual(fresh["endpoints"]["amf"], "127.0.0.5")
        self.assertEqual(buffer.snapshot(now=105)["rates"]["DL"]["pps"], 0)
        self.assertEqual(buffer.snapshot(now=200)["history"][-1]["DL"], 0)
        self.assertEqual(buffer.bins, {})
        self.assertEqual(buffer.snapshot(now=200)["totals"]["DL_packets"], 1)


class AssociationTests(unittest.TestCase):
    def sample(self, **core):
        return {"stale": False, "namespaces": {"core": {"updated": 100, "error": None, **core}},
                "links": [{"name": "N2", "status": "established"}]}

    def test_fresh_established(self):
        self.assertEqual(association_summary(self.sample(), now=120)["status"], "established")

    def test_stale_and_unknown_are_not_established(self):
        self.assertEqual(association_summary(self.sample(), now=146)["status"], "stale")
        self.assertEqual(association_summary(self.sample(error="unavailable"), now=120)["status"], "unknown")
        self.assertEqual(association_summary({}, now=120)["status"], "stale")
        sample = self.sample()
        sample["stale"] = True
        self.assertEqual(association_summary(sample, now=120)["status"], "stale")


class CaptureTests(unittest.TestCase):
    def test_missing_podman_and_stopped_capture(self):
        buffer = NgapBuffer()
        NgapCapture(None, buffer).run()
        self.assertEqual(buffer.snapshot()["status"], "error")
        capture = NgapCapture("/podman", NgapBuffer())
        capture.stop.set()
        with patch("ngap_trace.load_layout") as load:
            capture.run()
        load.assert_not_called()

    @patch("ngap_trace.load_layout", return_value=LAYOUT)
    @patch("ngap_trace.subprocess.Popen")
    @patch("ngap_trace.subprocess.run")
    def test_capture_reads_metadata_and_cleans_own_helper(self, run, popen, layout):
        buffer = NgapBuffer()
        capture = NgapCapture("/podman", buffer)
        process = Mock()
        process.stdout = io.StringIO("listening on lo, link-type EN10MB\n" + UL + "\n" + DL + "\n")
        process.wait.side_effect = lambda timeout: capture.stop.set() or 124
        popen.return_value = process
        capture.run()
        data = buffer.snapshot()
        self.assertEqual(data["status"], "live")
        self.assertEqual(data["totals"], {"UL_packets": 1, "UL_bytes": 106,
                                          "DL_packets": 1, "DL_bytes": 106})
        self.assertEqual(popen.call_args.args[0][-3:], ["sctp", "port", "38412"])
        creation = run.call_args_list[0].args[0]
        self.assertIn("--read-only", creation)
        self.assertNotIn("NET_ADMIN", creation)
        self.assertTrue(capture.helper.startswith("dpt-ngap-"))
        self.assertEqual(run.call_args.args[0], ["/podman", "rm", "-f", capture.helper])

    @patch("ngap_trace.load_layout", return_value=LAYOUT)
    @patch("ngap_trace.subprocess.Popen")
    @patch("ngap_trace.subprocess.run")
    def test_unexpected_exit_reports_error(self, run, popen, layout):
        buffer = NgapBuffer()
        capture = NgapCapture("/podman", buffer)
        process = Mock(stdout=io.StringIO("tcpdump: permission denied\n"))
        process.wait.return_value = 1
        popen.return_value = process
        capture.run()
        self.assertEqual(buffer.snapshot()["status"], "error")
        self.assertEqual(popen.call_count, 1)

    @patch("ngap_trace.load_layout", return_value=LAYOUT)
    @patch("ngap_trace.subprocess.run")
    def test_failed_creation_cleans_owned_helper(self, run, layout):
        run.side_effect = [subprocess.CalledProcessError(1, ["podman"]), Mock()]
        buffer = NgapBuffer()
        capture = NgapCapture("/podman", buffer)
        capture.run()
        self.assertEqual(buffer.snapshot()["status"], "error")
        self.assertEqual(run.call_args.args[0], ["/podman", "rm", "-f", capture.helper])

    @patch("ngap_trace.subprocess.run")
    def test_invalid_config_fails_closed(self, run):
        for result in ([], [{"component": "AMF", "service": "ngap", "address": "bad"}]):
            buffer = NgapBuffer()
            with patch("ngap_trace.load_layout", return_value=result):
                NgapCapture("/podman", buffer).run()
            self.assertEqual(buffer.snapshot()["status"], "error")
        with patch("ngap_trace.load_layout", side_effect=yaml.YAMLError()):
            buffer = NgapBuffer()
            NgapCapture("/podman", buffer).run()
            self.assertEqual(buffer.snapshot()["status"], "error")
        self.assertTrue(all(c.args[0][1:3] == ["rm", "-f"] for c in run.call_args_list))

    def test_helper_names_are_unique(self):
        self.assertNotEqual(NgapCapture("/podman", NgapBuffer()).helper,
                            NgapCapture("/podman", NgapBuffer()).helper)
    @patch("ngap_trace.load_layout", return_value=LAYOUT)
    @patch("ngap_trace.subprocess.Popen")
    @patch("ngap_trace.subprocess.run")
    def test_normal_timeout_rotates_without_recreating_helper(self, run, popen, layout):
        buffer = NgapBuffer()
        capture = NgapCapture("/podman", buffer)
        first = Mock(stdout=io.StringIO("listening on lo\n" + UL + "\n"))
        first.wait.return_value = 124
        second = Mock(stdout=io.StringIO("listening on lo\n" + DL + "\n"))
        second.wait.side_effect = lambda timeout: capture.stop.set() or 124
        popen.side_effect = [first, second]
        capture.run()
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(sum(c.args[0][1] == "run" for c in run.call_args_list), 1)
        self.assertEqual(buffer.snapshot()["totals"]["DL_packets"], 1)
        self.assertEqual(buffer.snapshot()["totals"]["UL_packets"], 1)


class CliTests(unittest.TestCase):
    def test_duration_validation(self):
        self.assertEqual(duration("0"), 0)
        self.assertEqual(duration("30"), 30)
        for value in ("-1", "86401"):
            with self.assertRaises(argparse.ArgumentTypeError):
                duration(value)

    @patch("ngap_cli.NgapCapture")
    @patch("ngap_cli.time.sleep", side_effect=KeyboardInterrupt)
    def test_interrupt_cleans_up(self, sleep, capture):
        with patch("sys.argv", ["ngap-monitor"]), patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(main(), 130)
        capture.return_value.start.assert_called_once()
        capture.return_value.close.assert_called_once()

    @patch("ngap_cli.NgapCapture")
    def test_capture_failure_returns_nonzero(self, capture):
        def fail():
            capture.call_args.args[1].set_status("error", "Test capture failure")
        capture.return_value.start.side_effect = fail
        with patch("sys.argv", ["ngap-monitor", "10"]), patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(main(), 2)
        capture.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
