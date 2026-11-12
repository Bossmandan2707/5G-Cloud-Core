import unittest

from ims.call_prep import gateway_configuration, validate_profile
from ims.preflight import provider_invites


class GatewayPreparationTests(unittest.TestCase):
    def setUp(self):
        self.profile = {
            "destination": "+12025550101",
            "external_caller_id": "+12025550100",
            "automatic_dial": False,
        }

    def test_configuration_is_disarmed_and_consumes_gate_before_dial(self):
        dialplan = gateway_configuration(self.profile)["extensions.conf"]
        self.assertIn("DPT_OUTBOUND_ARMED=0", dialplan)
        self.assertIn("TRYLOCK(dpt-outbound-gate)", dialplan)
        self.assertIn("DPT_PREFLIGHT_BLOCKED", dialplan)
        self.assertLess(dialplan.index("Set(GLOBAL(DPT_OUTBOUND_ARMED)=0)"),
                        dialplan.index("Dial(PJSIP/"))
        self.assertIn(",15,L(5000)", dialplan)

    def test_gateway_trusts_only_scscf_and_keeps_auth_separate(self):
        config = gateway_configuration(self.profile)["pjsip.conf"]
        self.assertIn("match=10.90.0.22/32", config)
        self.assertIn("endpoint_identifier_order=ip", config)
        self.assertIn("from_user=" + self.profile["external_caller_id"], config)
        self.assertIn("verify_server=yes", config)
        self.assertIn("#include dpt-trunk-auth.conf", config)
        self.assertNotIn("password=", config)
        self.assertNotIn("username=", config)

    def test_from_and_pai_use_mapped_number_without_overwriting_contact_identity(self):
        profile = {**self.profile, "caller_display_name": "test-connection",
                   "connection_username": "sip-login-fixture"}
        result = gateway_configuration(profile)
        endpoint, dialplan = result["pjsip.conf"], result["extensions.conf"]
        self.assertIn("from_user=" + profile["external_caller_id"], endpoint)
        self.assertIn("send_pai=yes", endpoint)
        self.assertIn("callerid=test-connection <" + profile["external_caller_id"] + ">", endpoint)
        self.assertIn("contact_user=sip-login-fixture", endpoint)
        self.assertIn("Set(CALLERID(num)=" + profile["external_caller_id"] + ")", dialplan)
        self.assertIn("Set(CALLERID(name)=test-connection)", dialplan)
        self.assertNotIn("PJSIP_HEADER(add,P-Asserted-Identity)", dialplan)

    def test_header_profile_fields_reject_config_injection(self):
        for field in ("caller_display_name", "connection_username"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    gateway_configuration({**self.profile, field: "bad\nsend_pai=no"})

    def test_invalid_numbers_and_automatic_dial_are_rejected(self):
        for field, value in (("destination", "1234"),
                             ("destination", "+12025550101\nsame => n,Dial(evil)"),
                             ("external_caller_id", "+1;bad"),
                             ("automatic_dial", True)):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    validate_profile({**self.profile, field: value})

    def test_provider_invites_excludes_received_ims_requests(self):
        text = ("<--- Received SIP request from UDP:10.90.0.22 --->\n"
                "INVITE sip:test@10.90.0.24 SIP/2.0\n"
                "<--- Transmitting SIP request to TLS:192.0.2.1:5061 --->\n"
                "INVITE sip:test@example.invalid SIP/2.0\n")
        self.assertEqual(provider_invites(text), 1)

    def test_call_time_limits_cannot_be_disabled(self):
        for field, value in (("ring_timeout_seconds", 0),
                             ("ring_timeout_seconds", 16),
                             ("maximum_answered_seconds", 6),
                             ("maximum_answered_seconds", True)):
            with self.subTest(field=field, value=value):
                with self.assertRaises(ValueError):
                    validate_profile({**self.profile, field: value})


if __name__ == "__main__":
    unittest.main()
