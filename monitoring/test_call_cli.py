import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ims import call_cli, start_cli
import ims_monitor


PROFILE = {"destination": "+12025550101", "external_caller_id": "+12025550102",
           "connection_username": "fixture"}


def gateway(command, *args):
    if command == "core show channels count":
        return "0 active channels\n"
    if command == "dialplan show globals":
        return "DPT_OUTBOUND_ARMED=0\n"
    if command == "pjsip show endpoint telnyx":
        return "from_user : +12025550102\ncontact_user : fixture\nsend_pai : true\n"
    return ""


class CallCliTests(unittest.TestCase):
    def test_idle_count_does_not_mistake_ten_channels_for_zero(self):
        self.assertTrue(call_cli.zero_channels("0 active channels\n0 active calls"))
        for text in ("10 active channels", "20 active channels", "", "unavailable"):
            self.assertFalse(call_cli.zero_channels(text))

    def test_temporary_gateway_age_uses_vm_not_host_clock(self):
        data = {"Config": {"Cmd": ["sleep", "1800"]},
                "State": {"StartedAt": "2026-11-09T12:00:00.123456789Z"}}
        with patch.object(call_cli.subprocess, "run",
                          return_value=SimpleNamespace(stdout="1794227401")) as run:
            import datetime
            start = datetime.datetime(2026, 11, 9, 12, tzinfo=datetime.timezone.utc).timestamp()
            run.return_value.stdout = str(int(start + 100))
            self.assertFalse(call_cli.gateway_expiring(data))
            run.return_value.stdout = str(int(start + 1501))
            self.assertTrue(call_cli.gateway_expiring(data))

    def test_temporary_gateway_cannot_refresh_when_busy(self):
        with patch.object(call_cli, "inspect", return_value={"State": {"Status": "running"}}), \
                patch.object(call_cli, "gateway_expiring", return_value=True), \
                patch.object(call_cli, "cli", return_value="10 active channels") as cli, \
                patch.object(call_cli.subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "not confirmed idle"):
                call_cli.ensure_gateway()
            cli.assert_called_once_with("core show channels count", False)
            run.assert_not_called()
    def test_readiness_is_read_only_and_requires_registered_contact(self):
        with patch.object(call_cli, "status", return_value={
            "verified": True, "msisdn": "fixture", "agent": {"address": "10.46.0.4"}}), \
                patch.object(start_cli, "verify_module", return_value={"verified": True}), \
                patch.object(call_cli, "inspect", return_value={
                    "State": {"Status": "running"}, "Config": {"Cmd": []}}), \
                patch.object(call_cli, "cli", side_effect=gateway) as cli, \
                patch.object(call_cli.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout="State: registered")) as run:
            self.assertTrue(call_cli.readiness(PROFILE)["ready"])
            run.return_value.stdout = "State: pending"
            self.assertFalse(call_cli.readiness(PROFILE)["ready"])
            self.assertTrue(all(c.args[0].startswith(("core show", "dialplan show", "pjsip show"))
                                for c in cli.call_args_list))

    def test_capture_start_failure_disarms_turns_off_logger_and_releases_lock(self):
        with tempfile.TemporaryDirectory() as root:
            private = Path(root)
            (private / "ims-client").mkdir()
            with patch.object(call_cli, "PRIVATE", private), \
                    patch.object(call_cli, "readiness", return_value={"ready": True}), \
                    patch.object(call_cli, "gateway_log", return_value=b""), \
                    patch.object(call_cli, "start", side_effect=RuntimeError("capture failed")), \
                    patch.object(call_cli, "cli", side_effect=gateway) as cli, \
                    patch.object(call_cli.os, "close", wraps=os.close) as close:
                with self.assertRaisesRegex(RuntimeError, "capture failed"):
                    call_cli.call(PROFILE)
                cli.assert_any_call("pjsip set logger off", False)
                cli.assert_any_call("dialplan set global DPT_OUTBOUND_ARMED 0")
                close.assert_called_once()
                with self.assertRaises(OSError):
                    os.fstat(close.call_args.args[0])

    def test_collection_failure_still_releases_lock_and_turns_logger_off(self):
        with tempfile.TemporaryDirectory() as root:
            private = Path(root)
            state = private / "ims-client"
            state.mkdir()
            folder = private / "traces/call-fixture"
            folder.mkdir(parents=True)
            request = "a" * 32
            (state / "call-status.json").write_text(json.dumps({
                "request_id": request, "state": "done"}))
            with patch.object(call_cli, "PRIVATE", private), \
                    patch.object(call_cli, "STATE", state), \
                    patch.object(call_cli.secrets, "token_hex", return_value=request), \
                    patch.object(call_cli, "readiness", return_value={"ready": True}), \
                    patch.object(call_cli, "gateway_log", return_value=b""), \
                    patch.object(call_cli, "start", return_value=folder), \
                    patch.object(call_cli, "collect", side_effect=RuntimeError("collect failed")), \
                    patch.object(call_cli, "cli", side_effect=gateway) as cli, \
                    patch.object(call_cli.subprocess, "run",
                                 return_value=SimpleNamespace(stdout="123")), \
                    patch.object(call_cli.os, "close", wraps=os.close) as close:
                with self.assertRaisesRegex(RuntimeError, "collect failed"):
                    call_cli.call(PROFILE, preflight=True)
                cli.assert_any_call("pjsip set logger off", False)
                close.assert_called_once()
                self.assertFalse(any(c.args[0].endswith("ARMED 1") for c in cli.call_args_list))

    def test_check_and_saved_trace_never_call_or_start(self):
        for option in ("--check", "--last-trace"):
            with self.subTest(option=option), \
                    patch("sys.argv", ["ue-call", option]), \
                    patch.object(call_cli, "load_profile", return_value=PROFILE), \
                    patch.object(call_cli, "readiness", return_value={"ready": True}), \
                    patch.object(call_cli, "last_result", return_value=(Path("/fixture"), {})), \
                    patch.object(call_cli, "show_trace"), \
                    patch.object(call_cli, "call") as call, \
                    patch.object(start_cli, "resume") as resume, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(call_cli.main(), 0)
                call.assert_not_called()
                resume.assert_not_called()

    def test_start_runs_frozen_baseline_resume_not_unchecked_up(self):
        with patch("sys.argv", ["ue-call", "--start", "--check"]), \
                patch.object(call_cli, "load_profile", return_value=PROFILE), \
                patch.object(call_cli, "readiness", return_value={"ready": True}), \
                patch.object(start_cli, "resume") as resume, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(call_cli.main(), 0)
            resume.assert_called_once_with()


class SavedEvidenceTests(unittest.TestCase):
    def test_dashboard_revalidates_result_and_resanitizes_trace(self):
        with tempfile.TemporaryDirectory() as root:
            private = Path(root)
            (private / "ims-client").mkdir()
            folder = private / "traces/call-fixture"
            folder.mkdir(parents=True)
            (private / "ims-client/latest-end-to-end-path").write_text(str(folder))
            report = {"ue_call": {"answered": True, "final_status": 200, "release_ok": True},
                      "gateway_dial_results": [{"status": "ANSWER", "cause": "16"}],
                      "password": "secret-fixture", "destination": "private-fixture"}
            path = folder / "end-to-end-result.json"
            path.write_text(json.dumps(report))
            (folder / "sip-trace.json").write_text(json.dumps({"events": [{
                "point": "ue", "message": "INVITE sip:fixture@example SIP/2.0\n"
                "Call-ID: fixture\nCSeq: 1 INVITE\nAuthorization: secret-fixture"}]}))
            value = ims_monitor.saved_call(private)
            self.assertTrue(value["passed"])
            self.assertEqual(len(value["ue_trace"]), 1)
            self.assertNotIn("secret-fixture", json.dumps(value))
            self.assertNotIn("private-fixture", json.dumps(value))
            report["ue_call"]["release_ok"] = False
            path.write_text(json.dumps(report))
            self.assertFalse(ims_monitor.saved_call(private)["passed"])

    def test_missing_or_outside_artifact_is_not_success(self):
        with tempfile.TemporaryDirectory() as root:
            private = Path(root)
            self.assertIsNone(ims_monitor.saved_call(private))
            (private / "ims-client").mkdir()
            (private / "ims-client/latest-end-to-end-path").write_text("/tmp/outside")
            self.assertIsNone(ims_monitor.saved_call(private))
