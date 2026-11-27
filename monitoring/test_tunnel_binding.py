import copy
import fcntl
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ims import runtime


CURRENT = {"ims": {"state": "PS-ACTIVE", "address": "10.46.0.6"},
           "internet": {"state": "PS-ACTIVE", "address": "10.45.0.6"}}
BINDING = {"interface": "uesimtun0", "address": "10.46.0.6"}


def interface(name, address):
    return {"ifname": name, "flags": ["UP"],
            "addr_info": [{"family": "inet", "local": address}]}


class TunnelSelectionTests(unittest.TestCase):
    def test_both_interface_orders_follow_ims_address_not_index(self):
        for name, other in (("uesimtun0", "uesimtun1"), ("uesimtun1", "uesimtun0")):
            rows = [interface(other, "10.45.0.6"), interface(name, "10.46.0.6")]
            self.assertEqual(runtime.select_ims_tunnel(CURRENT, rows, "10.46.0.0/16"),
                             {"interface": name, "address": "10.46.0.6"})

    def test_missing_ambiguous_down_and_non_ue_tunnels_are_rejected(self):
        good = interface("uesimtun0", "10.46.0.6")
        for rows in ([], [good, interface("uesimtun1", "10.46.0.6")],
                     [dict(good, flags=[])], [interface("eth0", "10.46.0.6")]):
            with self.subTest(rows=rows), self.assertRaises(RuntimeError):
                runtime.select_ims_tunnel(CURRENT, rows, "10.46.0.0/16")

    def test_inactive_out_of_subnet_invalid_or_shared_session_is_rejected(self):
        for changes in ({"state": "PS-ACTIVE-PENDING"}, {"address": "10.45.0.6"},
                        {"address": "invalid"}):
            current = copy.deepcopy(CURRENT)
            current["ims"].update(changes)
            with self.assertRaises((RuntimeError, ValueError)):
                runtime.select_ims_tunnel(current, [], "10.46.0.0/16")
        current = copy.deepcopy(CURRENT)
        current["internet"]["address"] = current["ims"]["address"]
        with self.assertRaisesRegex(RuntimeError, "must differ"):
            runtime.select_ims_tunnel(current, [], "10.46.0.0/16")

    def test_wrong_agent_address_cannot_trigger_ipsec_checks_or_verify(self):
        with patch.object(runtime, "identity", return_value=("fixture", "4599999977", "example")), \
                patch.object(runtime, "running", return_value=True), \
                patch.object(runtime, "ue_sessions", return_value=CURRENT), \
                patch.object(runtime, "agent_status", return_value={
                    "registration_observed": True, "address": "10.45.0.6"}), \
                patch.object(runtime, "scscf_contact", return_value={
                    "registered": True, "contacts": [{"uri": "sip:10.46.0.6:5060",
                                                     "expires_in": 300}]}), \
                patch.object(runtime, "podman", return_value=SimpleNamespace(
                    stdout=b"1000", returncode=0)) as podman:
            self.assertFalse(runtime.status()["verified"])
            self.assertFalse(any("xfrm" in c.args for c in podman.call_args_list))


class AgentBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.client = Path(self.temp.name)
        self.state = self.client / "state"
        self.state.mkdir()
        for attr, value in (("CLIENT", self.client), ("STATE", self.state)):
            context = patch.object(runtime, attr, value)
            context.start()
            self.addCleanup(context.stop)

    def test_stopped_agent_gets_atomic_owner_only_binding(self):
        with patch.object(runtime, "inspect", return_value={"State": {"Status": "exited"}}), \
                patch.object(runtime, "stop") as stop:
            runtime.bind_agent(BINDING)
            path = self.state / "tunnel-binding"
            self.assertEqual(path.read_text(), "uesimtun0\n10.46.0.6\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(self.state.glob(".tunnel-binding-*")), [])
            stop.assert_not_called()

    def test_active_call_refuses_rebind_without_modifying_state(self):
        (self.state / "status.json").write_text(json.dumps({"call_active": True}))
        with patch.object(runtime, "inspect", return_value={"State": {"Status": "running"}}), \
                patch.object(runtime, "stop") as stop:
            with self.assertRaisesRegex(RuntimeError, "call active"):
                runtime.bind_agent(BINDING)
            self.assertFalse((self.state / "tunnel-binding").exists())
            stop.assert_not_called()

    def test_cli_lock_refuses_rebind(self):
        with (self.client / "call-cli.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(runtime, "inspect") as inspect:
                with self.assertRaisesRegex(RuntimeError, "call command active"):
                    runtime.bind_agent(BINDING)
                inspect.assert_not_called()

    def test_busy_gateway_refuses_rebind(self):
        with patch.object(runtime, "inspect", return_value={"State": {"Status": "running"}}), \
                patch.object(runtime, "running", return_value=True), \
                patch.object(runtime, "podman",
                             return_value=SimpleNamespace(stdout=b"10 active channels")), \
                patch.object(runtime, "stop") as stop:
            with self.assertRaisesRegex(RuntimeError, "not idle"):
                runtime.bind_agent(BINDING)
            stop.assert_not_called()

    def test_correct_binding_keeps_running_agent_untouched(self):
        path = self.state / "tunnel-binding"
        path.write_text("uesimtun0\n10.46.0.6\n")
        (self.state / "status.json").write_text(json.dumps(BINDING))
        before = path.stat().st_mtime_ns
        with patch.object(runtime, "inspect", return_value={"State": {"Status": "running"}}), \
                patch.object(runtime, "stop") as stop:
            runtime.bind_agent(BINDING)
            self.assertEqual(path.stat().st_mtime_ns, before)
            stop.assert_not_called()

    def test_idle_wrong_binding_stops_only_agent_before_publish(self):
        def stopped():
            self.assertFalse((self.state / "tunnel-binding").exists())
        with patch.object(runtime, "inspect", return_value={"State": {"Status": "running"}}), \
                patch.object(runtime, "running", return_value=True), \
                patch.object(runtime, "podman",
                             return_value=SimpleNamespace(stdout=b"0 active channels\n")), \
                patch.object(runtime, "stop", side_effect=stopped) as stop:
            runtime.bind_agent(BINDING)
            stop.assert_called_once_with()
            self.assertTrue((self.state / "tunnel-binding").exists())

    def test_symlinked_binding_is_refused(self):
        target = self.client / "other"
        target.write_text("untouched")
        (self.state / "tunnel-binding").symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symlinked"):
            runtime.bind_agent(BINDING)
        self.assertEqual(target.read_text(), "untouched")
