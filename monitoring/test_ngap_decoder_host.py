import io
import json
import unittest
from unittest.mock import Mock, patch

from ngap_decode import DecoderBuffer, NgapDecoder, validate_event
from ngap_cli import main
from test_ngap_decode import decoder, pdml
from test_ngap_trace import LAYOUT


def event():
    return decoder.decode_packet(pdml())[0]


class BufferTests(unittest.TestCase):
    def test_bounded_history_and_copy_isolation(self):
        buffer = DecoderBuffer(limit=2)
        buffer.configure("127.0.0.5", "127.0.0.1", 38412)
        for _ in range(4):
            buffer.accept({"type": "event", "event": event()})
        snapshot = buffer.snapshot()
        self.assertEqual(snapshot["total_events"], 4)
        self.assertEqual([e["id"] for e in snapshot["events"]], [3, 4])
        self.assertEqual(snapshot["events"][0]["direction"], "UL")
        snapshot["events"][0]["message"] = "Changed"
        self.assertEqual(buffer.snapshot()["events"][0]["message"], "NGSetupRequest")

    def test_states_and_no_raw_diagnostics(self):
        buffer = DecoderBuffer()
        buffer.accept({"type": "ready"})
        self.assertEqual(buffer.snapshot()["status"], "live")
        self.assertEqual(buffer.snapshot()["events"], [])
        buffer.accept({"type": "warning", "reason": "truncated_decoder_output"})
        buffer.accept({"type": "error", "reason": "PRIVATE_DIAGNOSTIC"})
        self.assertEqual(buffer.snapshot()["rejected_records"], 1)
        self.assertEqual(buffer.snapshot()["status"], "error")
        self.assertNotIn("PRIVATE", json.dumps(buffer.snapshot()))

    def test_reject_unsafe_or_out_of_schema_records(self):
        endpoints = {"amf": "127.0.0.5", "gnb": "127.0.0.1", "port": 38412}
        for replacement in ({"raw": "PRIVATE"}, {"timestamp": float("nan")},
                            {"source": "192.0.2.1"}, {"message": "<script>PRIVATE</script>"},
                            {"ran_context_id": -1}, {"outcome": "guessed"},
                            {"causes": [{"category": "raw", "value": "PRIVATE"}]},
                            {"source_port": 1, "destination_port": 2}):
            with self.subTest(replacement=replacement):
                with self.assertRaises((ValueError, TypeError)):
                    validate_event({**event(), **replacement}, endpoints)


class CaptureTests(unittest.TestCase):
    def test_missing_podman_and_stopped_capture(self):
        buffer = DecoderBuffer()
        NgapDecoder(None, buffer).run()
        self.assertEqual(buffer.snapshot()["status"], "error")
        capture = NgapDecoder("/podman", DecoderBuffer())
        capture.stop.set()
        with patch("ngap_decode.subprocess.run") as run:
            capture.run()
            run.assert_not_called()

    @patch("ngap_decode.subprocess.run")
    def test_missing_image_is_actionable(self, run):
        run.return_value.returncode = 1
        buffer = DecoderBuffer()
        NgapDecoder("/podman", buffer).run()
        self.assertEqual(buffer.snapshot()["status"], "error")
        self.assertIn("podman build", buffer.snapshot()["message"])
        self.assertFalse(any(c.args[0][1] == "run" for c in run.call_args_list))

    @patch("ngap_decode.load_layout", return_value=LAYOUT)
    @patch("ngap_decode.subprocess.Popen")
    @patch("ngap_decode.subprocess.run")
    def test_capture_accepts_only_sanitized_records_and_cleans_owned_helper(self, run, popen, layout):
        run.return_value.returncode = 0
        buffer = DecoderBuffer()
        capture = NgapDecoder("/podman", buffer)
        records = [{"type": "ready"}, {"type": "event", "event": event()},
                   {"type": "event", "event": {**event(), "raw": "PRIVATE"}}]
        process = Mock(stdout=io.StringIO("\n".join(map(json.dumps, records)) + "\n"))
        process.wait.side_effect = lambda timeout: capture.stop.set() or 124
        popen.return_value = process
        capture.run()
        snapshot = buffer.snapshot()
        self.assertEqual(snapshot["status"], "live")
        self.assertEqual(snapshot["total_events"], 1)
        self.assertEqual(snapshot["rejected_records"], 1)
        self.assertNotIn("PRIVATE", json.dumps(snapshot))
        creation = next(c.args[0] for c in run.call_args_list if c.args[0][1] == "run")
        self.assertIn("--read-only", creation)
        self.assertIn("--tmpfs", creation)
        self.assertNotIn("NET_ADMIN", creation)
        self.assertEqual(run.call_args.args[0], ["/podman", "rm", "-f", capture.helper])

    @patch("ngap_decode.load_layout", return_value=LAYOUT)
    @patch("ngap_decode.subprocess.Popen")
    @patch("ngap_decode.subprocess.run")
    def test_rotation_keeps_buffer_and_unexpected_exit_stops(self, run, popen, layout):
        run.return_value.returncode = 0
        buffer = DecoderBuffer()
        capture = NgapDecoder("/podman", buffer)
        first = Mock(stdout=io.StringIO('{"type":"ready"}\n'))
        first.wait.return_value = 124
        second = Mock(stdout=io.StringIO('{"type":"error","reason":"failure"}\n'))
        second.wait.return_value = 2
        popen.side_effect = [first, second]
        capture.run()
        self.assertEqual(popen.call_count, 2)
        self.assertEqual(buffer.snapshot()["status"], "error")
        self.assertEqual(sum(c.args[0][1] == "run" for c in run.call_args_list), 1)


class CliTests(unittest.TestCase):
    @patch("ngap_cli.NgapDecoder")
    @patch("ngap_cli.time.sleep", side_effect=KeyboardInterrupt)
    def test_decode_prints_ladder_and_cleans_up(self, sleep, capture):
        def ready():
            buffer = capture.call_args.args[1]
            buffer.configure("127.0.0.5", "127.0.0.1", 38412)
            buffer.accept({"type": "ready"})
            buffer.accept({"type": "event", "event": event()})
        capture.return_value.start.side_effect = ready
        with patch("sys.argv", ["ngap-monitor", "--decode", "30"]):
            with patch("sys.stdout", new_callable=io.StringIO) as output:
                self.assertEqual(main(), 130)
        self.assertIn("NGSetupRequest", output.getvalue())
        self.assertIn("gNB ---> AMF", output.getvalue())
        capture.return_value.close.assert_called_once()

    @patch("ngap_cli.NgapDecoder")
    def test_decode_error_nonzero_and_cleanup(self, capture):
        capture.return_value.start.side_effect = lambda: capture.call_args.args[1].set_status("error", "Missing image")
        with patch("sys.argv", ["ngap-monitor", "--decode", "30"]), patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(main(), 2)
        capture.return_value.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
