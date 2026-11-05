import hashlib
import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from ims import lab
import ims_monitor


def reference_compose():
    return {"services": {name: {"image": "upstream", "privileged": True,
                               "ports": ["8080:8080"], "depends_on": ["amf", "dns"],
                               "volumes": [f"./{name}:/mnt/{name}"],
                               "environment": ["COMPONENT_NAME=" + name.upper()]}
                         for name in (*lab.SERVICES, "amf", "smf", "upf")}}


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.config = lab.settings()
        self.core = (lab.ROOT / "open5gs-pod.yaml").read_text()

    def test_bundle_has_only_ims_and_no_public_ports_or_privileged_mode(self):
        result = lab.compose_bundle(reference_compose(), self.config)
        self.assertEqual(set(result["services"]), set(lab.SERVICES))
        for service in result["services"].values():
            self.assertFalse(service["privileged"])
            self.assertEqual(service["ports"], [])
            self.assertNotIn("amf", service["depends_on"])
        self.assertIn("dpt-userspace.sh", result["services"]["rtpengine"]["entrypoint"][0])

    def test_core_overlay_preserves_internet_and_adds_ims(self):
        result = lab.core_overlay(self.core, self.config)
        docs = list(yaml.safe_load_all(result))
        cm = next(d for d in docs if d["kind"] == "ConfigMap")
        smf = yaml.safe_load(cm["data"]["smf.yaml"])["smf"]
        upf = yaml.safe_load(cm["data"]["upf.yaml"])["upf"]
        self.assertEqual([s["dnn"] for s in smf["session"]], ["internet", "ims"])
        self.assertEqual(upf["session"][-1]["dev"], "ogstun2")
        self.assertEqual(smf["p-cscf"], ["10.90.0.20"])
        self.assertIn("scp.yaml", cm["data"])
        self.assertIn("bsf.yaml", cm["data"])
        self.assertNotEqual(self.core, result)
        self.assertEqual((lab.ROOT / "open5gs-pod.yaml").read_text(), self.core)
        lab.validate_bundle(lab.compose_bundle(reference_compose(), self.config), result, self.config)

    def test_overlay_rejects_duplicate_ims(self):
        once = lab.core_overlay(self.core, self.config)
        with self.assertRaises(ValueError):
            lab.core_overlay(once, self.config)

    def test_unknown_upf_startup_is_not_silently_patched(self):
        with self.assertRaises(ValueError):
            lab.core_overlay(self.core.replace("# N6 NAT", "# replaced marker"), self.config)

    def test_private_runtime_rejects_repo_path(self):
        with self.assertRaises(ValueError):
            lab.runtime_directory(lab.ROOT / "ims/private")

    def test_private_file_permissions_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config"
            lab.private_write(path, "fixture")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            link = Path(folder) / "link"
            link.symlink_to(path)
            with self.assertRaises(ValueError):
                lab.private_write(link, "overwrite")
            self.assertEqual(path.read_text(), "fixture")

    def test_archive_checksum_is_required(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                lab.extract_reference(b"invalid", Path(folder), "0" * 64)

    def test_archive_traversal_rejected(self):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode="w:gz") as tar:
            member = tarfile.TarInfo("root/../escape")
            member.size = 1
            tar.addfile(member, io.BytesIO(b"x"))
        data = out.getvalue()
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                lab.extract_reference(data, Path(folder), hashlib.sha256(data).hexdigest())

    def test_sql_moves_to_stdin_and_removes_password_flag(self):
        source = 'X=$(mysql -h "$MYSQL_IP" --password=linux -N -s -e "SELECT 1")\n'
        rewritten = lab.secure_mysql_commands(source)
        self.assertNotIn("--password", rewritten)
        self.assertNotIn(' -e "SELECT', rewritten)
        self.assertIn("| mysql", rewritten)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh") as script:
            script.write("#!/bin/bash\n" + rewritten)
            script.flush()
            subprocess.run(["bash", "-n", script.name], check=True, capture_output=True)

    def test_realm_pads_two_digit_mnc(self):
        self.assertEqual(self.config["realm"], "ims.mnc005.mcc999.3gppnetwork.org")

    def test_invalid_address_and_exposure_rejected(self):
        result = lab.compose_bundle(reference_compose(), self.config)
        result["services"]["pyhss"]["ports"] = ["8080:8080"]
        with self.assertRaises(ValueError):
            lab.validate_bundle(result, lab.core_overlay(self.core, self.config), self.config)

    @patch("ims.lab.subprocess.run")
    def test_start_without_approval_does_nothing(self, run):
        with self.assertRaises(ValueError):
            lab.start("/unused", False, False)
        run.assert_not_called()

    @patch("ims.lab.subprocess.run")
    @patch("ims.lab.subprocess.check_output", return_value="1951")
    def test_current_low_memory_cannot_activate(self, memory, run):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                lab.start(folder, True, True)
        run.assert_not_called()


class ImsMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.config = ims_monitor.topology()

    def test_absent_containers_are_not_deployed_not_healthy(self):
        data = ims_monitor.build_snapshot(self.config, {}, {}, [], True, now=100)
        self.assertTrue(all(r["container_status"] == "not deployed" for r in data["services"]))
        self.assertTrue(all(v is None for v in data["verification"].values()))
        self.assertTrue(all(v is None for v in data["counters"].values()))

    def test_unavailable_inventory_is_unknown(self):
        data = ims_monitor.build_snapshot(self.config, None, {}, ["unavailable"], True)
        self.assertTrue(all(r["container_status"] == "unknown" for r in data["services"]))

    def test_running_socket_does_not_prove_registration(self):
        listeners = {"pcscf": [{"address": "10.90.0.20", "port": 5060, "protocol": "udp"}]}
        data = ims_monitor.build_snapshot(self.config, {"dpt-ims-pcscf": "running"}, listeners, [], True, now=100)
        pcscf = next(s for s in data["services"] if s["name"] == "pcscf")
        self.assertTrue(pcscf["listener_observed"])
        self.assertIsNone(data["verification"]["handset_vonr"])
        self.assertIsNone(data["counters"]["active_calls"])

    def test_stale_listener_observation_is_cleared(self):
        monitor = ims_monitor.ImsMonitor(None)
        monitor.data = ims_monitor.build_snapshot(self.config, {"dpt-ims-pcscf": "running"}, {}, [], True, now=100)
        data = monitor.snapshot(now=146)
        self.assertTrue(data["stale"])
        self.assertTrue(all(s["container_status"] == "stale" for s in data["services"]))

    def test_topology_metadata_has_no_credentials(self):
        self.assertEqual(set(self.config["services"]["pyhss"]), {"address", "port", "protocol"})


if __name__ == "__main__":
    unittest.main()
