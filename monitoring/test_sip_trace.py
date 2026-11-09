import unittest

from ims.sip_trace import messages


class SipTraceTests(unittest.TestCase):
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
