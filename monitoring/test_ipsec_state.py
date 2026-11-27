import unittest

from ims.ipsec_state import associations, peer_health


class IpsecEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.agent = {"address": "192.0.2.2", "pcscf_server_spi": 4099,
                      "pcscf_client_spi": 4098, "ue_client_spi": 256, "ue_server_spi": 257}
        self.rows = [
            {"src": "192.0.2.2", "dst": "192.0.2.1", "spi": spi, "mode": "transport"}
            for spi in (4098, 4099)
        ] + [
            {"src": "192.0.2.1", "dst": "192.0.2.2", "spi": spi, "mode": "transport"}
            for spi in (256, 257)
        ]

    def test_missing_negotiated_peer_spi_blocks_verification(self):
        healthy = peer_health(self.agent, "192.0.2.1", self.rows, self.rows)
        self.assertTrue(healthy["verified"])
        stale = peer_health(self.agent, "192.0.2.1", self.rows, self.rows[1:])
        self.assertFalse(stale["verified"])
        self.assertEqual(stale["missing"][0]["side"], "P-CSCF")

    def test_parser_discards_all_key_fields(self):
        text = ("src 192.0.2.2 dst 192.0.2.1\n"
                " proto esp spi 0x00001003 reqid 4099 mode transport\n"
                " auth-trunc hmac(sha1) private-integrity-fixture 96\n"
                " enc cipher_null private-encryption-fixture\n")
        rows = associations(text)
        self.assertEqual(rows[0]["spi"], 4099)
        self.assertNotIn("private", str(rows))

    def test_absent_negotiated_metadata_is_not_verified(self):
        self.assertFalse(peer_health({}, "192.0.2.1", self.rows, self.rows)["verified"])
