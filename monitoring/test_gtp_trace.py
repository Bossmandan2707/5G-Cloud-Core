import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from gtp_trace import GtpCapture, TraceBuffer, parse_packet, read_ue_identity


UL = "1760352000.123456 IP 127.0.0.1.2152 > 127.0.0.7.2152: UDP, length 1448"
DL = "1760352001.654321 IP 127.0.0.7.2152 > 127.0.0.1.2152: UDP, length 100"

class IdentityTests(unittest.TestCase):
    def test_configured_imsi_and_two_digit_mnc(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ue-pod.yaml"
            path.write_text("    supi: 'imsi-999050000000001'\n    mcc: '999'\n    mnc: '05'\n")
            identity = read_ue_identity(path)
            self.assertEqual(identity["imsi"], "999050000000001")
            self.assertEqual(identity["mnc"], "05")
            self.assertEqual(identity["status"], "configured")

    def test_mismatched_plmn_is_not_reported_as_configured(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ue-pod.yaml"
            path.write_text("    supi: 'imsi-999050000000001'\n    mcc: '998'\n    mnc: '01'\n")
            self.assertEqual(read_ue_identity(path)["status"], "unknown")

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(read_ue_identity(Path(folder) / "missing")["status"], "unknown")


class PacketTests(unittest.TestCase):
    def test_uplink(self):
        packet = parse_packet(UL)
        self.assertEqual(packet["direction"], "UL")
        self.assertEqual(packet["bytes"], 1448)
        self.assertEqual(packet["source_port"], 2152)
        self.assertEqual(packet["timestamp"], 1760352000.123456)

    def test_downlink(self):
        self.assertEqual(parse_packet(DL)["direction"], "DL")

    def test_other_path(self):
        self.assertEqual(parse_packet(UL.replace("127.0.0.1", "127.0.0.4"))["direction"], "OTHER")

    def test_ignore_diagnostics_and_other_protocols(self):
        for line in ("listening on lo", "garbage", UL.replace("2152", "53")):
            self.assertIsNone(parse_packet(line))


class BufferTests(unittest.TestCase):
    def test_bounded_history_with_cumulative_totals(self):
        trace = TraceBuffer(limit=2)
        for _ in range(5):
            trace.add(parse_packet(UL), now=100)
        data = trace.snapshot(now=100)
        self.assertEqual([p["id"] for p in data["packets"]], [4, 5])
        self.assertEqual(data["totals"]["UL_packets"], 5)
        self.assertEqual(data["totals"]["UL_bytes"], 5 * 1448)

    def test_rates_and_idle_expiry(self):
        trace = TraceBuffer()
        trace.add(parse_packet(UL), now=100)
        trace.add(parse_packet(DL), now=101)
        data = trace.snapshot(now=102)
        self.assertAlmostEqual(data["rates"]["UL"]["mbps"], 1448 * 8 / 5 / 1e6)
        self.assertEqual(data["rates"]["DL"]["pps"], 0.2)
        self.assertEqual(trace.snapshot(now=106)["rates"]["DL"]["mbps"], 0)
        self.assertEqual(trace.snapshot(now=200)["rates"]["UL"]["mbps"], 0)
        self.assertEqual(trace.bins, {})
        self.assertEqual(len(trace.snapshot(now=200)["history"]), 60)

    def test_capture_identity_is_not_a_fake_imsi(self):
        data = TraceBuffer().snapshot()
        self.assertIn("not identified", data["subscriber"])
        self.assertEqual(data["packets"], [])


class CaptureTests(unittest.TestCase):
    @patch("gtp_trace.subprocess.run")
    def test_stopped_capture_does_not_create_helper(self, run):
        capture = GtpCapture("/podman", TraceBuffer())
        capture.stop.set()
        capture.run()
        run.assert_not_called()

    def test_reap_process_closes_pipe_and_waits(self):
        capture = GtpCapture("/podman", TraceBuffer())
        capture.process = Mock()
        capture.process.poll.return_value = None
        capture._reap_process()
        capture.process.terminate.assert_called_once()
        capture.process.wait.assert_called_once_with(timeout=5)
        capture.process.stdout.close.assert_called_once()

    def test_reap_process_kills_unresponsive_exec(self):
        capture = GtpCapture("/podman", TraceBuffer())
        capture.process = Mock()
        capture.process.poll.return_value = None
        capture.process.wait.side_effect = [subprocess.TimeoutExpired("podman", 5), 0]
        capture._reap_process()
        capture.process.kill.assert_called_once()
        self.assertEqual(capture.process.wait.call_count, 2)
    def test_missing_podman(self):
        trace = TraceBuffer()
        GtpCapture(None, trace).run()
        self.assertEqual(trace.snapshot()["status"], "error")

    @patch("gtp_trace.subprocess.run")
    def test_failed_helper_creation_reports_error_and_cleans_up(self, run):
        run.side_effect = [subprocess.CalledProcessError(1, ["podman"]), Mock()]
        trace = TraceBuffer()
        capture = GtpCapture("/podman", trace)
        capture.run()
        self.assertEqual(trace.snapshot()["status"], "error")
        self.assertEqual(run.call_args.args[0], ["/podman", "rm", "-f", capture.helper])

    @patch("gtp_trace.subprocess.Popen")
    @patch("gtp_trace.subprocess.run")
    def test_capture_reads_metadata_and_removes_its_helper(self, run, popen):
        trace = TraceBuffer()
        capture = GtpCapture("/podman", trace)
        process = Mock()
        process.stdout = io.StringIO("listening on lo, link-type EN10MB\n" + UL + "\n" + DL + "\n")
        process.wait.side_effect = lambda timeout: capture.stop.set() or 124
        popen.return_value = process
        capture.run()
        data = trace.snapshot()
        self.assertEqual(data["status"], "live")
        self.assertEqual(data["totals"]["UL_packets"], 1)
        self.assertEqual(data["totals"]["DL_packets"], 1)
        self.assertIn("timeout", popen.call_args.args[0])
        self.assertIn("45", popen.call_args.args[0])
        self.assertEqual(run.call_args.args[0], ["/podman", "rm", "-f", capture.helper])


if __name__ == "__main__":
    unittest.main()
