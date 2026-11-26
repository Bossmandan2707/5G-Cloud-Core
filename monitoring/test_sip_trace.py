import unittest

from ims.sip_trace import messages


class SipTraceTests(unittest.TestCase):
    def test_static_ue_pani_is_visible_without_exposing_authentication(self):
        pani = "3GPP-NR-TDD;utran-cell-id-3gpp=99905000001000000010"
        packet = ("INVITE sip:fixture@ims.example SIP/2.0\r\n"
                  "Call-ID: fixture\r\nCSeq: 1 INVITE\r\n"
                  "P-Access-Network-Info: " + pani + "\r\n"
                  "Authorization: private-fixture\r\n\r\n").encode()
        event = messages(packet, "ue")[0]
        self.assertEqual(event["headers"]["p-access-network-info"], pani)
        self.assertIn(pani, event["message"])
        self.assertNotIn("private-fixture", str(event))
    def test_trace_never_exposes_authorization_or_unknown_secret_headers(self):
        packet = (b"INVITE sip:+12025550101@ims.example SIP/2.0\r\n"
                  b"From: <sip:4599999977@ims.example>\r\n"
                  b"To: <sip:+12025550101@ims.example>\r\n"
                  b"Call-ID: fixture\r\nCSeq: 1 INVITE\r\n"
                  b"Proxy-Authorization: Digest response=\"private-fixture\"\r\n"
                  b"X-Private-Key: private-fixture\r\n\r\n")
        events = messages(packet, "ue")
        self.assertEqual(len(events), 1)
        self.assertNotIn("private-fixture", str(events))
        self.assertNotIn("Authorization", events[0]["message"])
        self.assertIn("4599999977", events[0]["message"])

    def test_options_response_is_not_an_answered_invite(self):
        packet = b"SIP/2.0 200 OK\r\nCall-ID: options\r\nCSeq: 1 OPTIONS\r\n\r\n"
        self.assertEqual(messages(packet, "b2bua"), [])
