import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ims.registration_state import agent_status, scscf_contact, sessions


class RegistrationEvidenceTests(unittest.TestCase):
    def test_pending_session_is_not_active(self):
        data = sessions("PDU Session1:\n state: PS-ACTIVE-PENDING\n apn: ims\n address: null\n")
        self.assertNotEqual(data["ims"]["state"], "PS-ACTIVE")

    def test_msisdn_contact_requires_registered_state_and_positive_expiry(self):
        impu = "sip:4599999977@ims.example"
        text = "{\n impu: " + impu + "\n state: REGISTERED\n contacts: {\n" \
               " sip:192.0.2.2:5060: {\n expires: 300\n client: test\n }\n }\n}"
        self.assertTrue(scscf_contact(text, impu)["registered"])
        self.assertFalse(scscf_contact(text.replace("300", "-1"), impu)["registered"])
        self.assertFalse(scscf_contact(text.replace("REGISTERED", "UNREGISTERED"), impu)["registered"])
        self.assertIsNone(scscf_contact(text, "sip:other@ims.example")["registered"])
        self.assertFalse(scscf_contact("", impu)["registered"])

    def test_stale_or_expired_agent_cannot_claim_registration(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "status.json"
            value = {"state": "registered", "registered": True, "protected": True,
                     "msisdn_associated": True, "updated_at": 100, "expires_at": 700,
                     "password": "private-fixture"}
            path.write_text(json.dumps(value))
            self.assertTrue(agent_status(path, now=105)["registration_observed"])
            self.assertFalse(agent_status(path, now=120)["registration_observed"])
            self.assertFalse(agent_status(path, now=701)["registration_observed"])
            self.assertNotIn("password", agent_status(path, now=105))
            os.utime(path, (0, 0))
            self.assertFalse(agent_status(path, now=105)["registration_observed"])

    def test_vm_clock_reference_does_not_bypass_host_receipt_freshness(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "status.json"
            path.write_text(json.dumps({
                "registered": True, "protected": True, "msisdn_associated": True,
                "updated_at": 100, "expires_at": 700}))
            os.utime(path, (10000, 10000))
            with patch("ims.registration_state.time.time", return_value=10005):
                self.assertTrue(agent_status(path, now=105)["registration_observed"])
            with patch("ims.registration_state.time.time", return_value=10030):
                self.assertFalse(agent_status(path, now=105)["registration_observed"])
