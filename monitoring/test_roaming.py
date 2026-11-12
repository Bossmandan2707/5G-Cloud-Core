import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "roaming/partners/three-uk.yaml"


class ThreeUkPlanningTests(unittest.TestCase):
    def setUp(self):
        self.profile = yaml.safe_load(PROFILE.read_text())

    def test_profile_is_explicitly_inactive_and_not_native_config(self):
        p = self.profile
        self.assertEqual(p["schema_version"], 1)
        self.assertEqual(p["profile_type"], "s8hr-partner-planning")
        self.assertEqual(p["status"], "draft-inactive")
        self.assertIs(p["enabled"], False)
        self.assertEqual(p["agreement_status"], "not-established")
        self.assertIs(p["operator_parameters_confirmed"], False)
        self.assertEqual(p["direction"], "inbound")
        self.assertEqual(p["architecture"], "LTE-EPC-S8HR")
        for key in ("apiVersion", "kind", "sepp", "mme", "sgwc", "sgwu"):
            self.assertNotIn(key, p)

    def test_home_plmn_preserves_string_identity_and_allocation_source(self):
        home = self.profile["home_network"]
        self.assertEqual(home["plmn"], {"mcc": "234", "mnc": "20"})
        self.assertEqual(home["allocation_holder"], "Hutchison 3G UK Ltd")
        self.assertTrue(home["allocation_source"].startswith("https://www.ofcom.org.uk/"))
        self.assertIsInstance(home["allocation_checked_on"], str)
        self.assertEqual(home["reference_only_additional_allocations"],
                         [{"mcc": "235", "mnc": "94", "included_in_profile_scope": False}])

    def test_visited_identity_matches_existing_lab_without_replacing_plmn(self):
        config = next(yaml.safe_load_all((ROOT / "open5gs-pod.yaml").read_text()))
        amf = yaml.safe_load(config["data"]["amf.yaml"])["amf"]
        visited = self.profile["visited_network"]["plmn"]
        self.assertEqual(visited, {"mcc": "999", "mnc": "05"})
        self.assertEqual(visited, amf["plmn_support"][0]["plmn_id"])
        self.assertNotIn(str(PROFILE.relative_to(ROOT)),
                         (ROOT / "open5gs-pod.yaml").read_text())

    def test_identification_envelope_is_not_an_admission_allowlist(self):
        p = self.profile
        imsi = p["imsi"]
        prefix = p["home_network"]["plmn"]["mcc"] + p["home_network"]["plmn"]["mnc"]
        self.assertEqual(imsi["home_plmn_prefix"], prefix)
        self.assertEqual(imsi["length"], 15)
        self.assertEqual(imsi["operator_authorized_ranges"], [])
        self.assertEqual(imsi["admission_policy"], "deny-until-operator-approved")
        envelope = imsi["identification_envelope"]
        self.assertEqual(envelope["first"], prefix + "0" * 10)
        self.assertEqual(envelope["last"], prefix + "9" * 10)
        for value in (envelope["first"], envelope["last"], prefix + "1234567890"):
            self.assertIsInstance(value, str)
            self.assertIsNotNone(re.fullmatch(imsi["identification_pattern"], value))
        for value in ("235941234567890", "234151234567890", "999050000000001",
                      prefix, prefix + "0" * 11):
            self.assertIsNone(re.fullmatch(imsi["identification_pattern"], value))

    def test_s8_has_correct_roles_and_ports_without_endpoints(self):
        s8 = self.profile["s8"]
        self.assertIs(s8["enabled"], False)
        for key, interface, local, remote, protocol, port in (
                ("control_plane", "S8-C", "SGW-C", "PGW-C", "GTPv2-C", 2123),
                ("user_plane", "S8-U", "SGW-U", "PGW-U", "GTP-U", 2152)):
            row = s8[key]
            self.assertEqual((row["interface"], row["local_function"], row["remote_function"],
                              row["protocol"], row["transport"], row["port"]),
                             (interface, local, remote, protocol, "UDP", port))
            for field in ("local_bind_address", "local_advertised_address", "remote_address"):
                self.assertIsNone(row[field])
        self.assertEqual(s8["operator_approved_apns"], [])
        self.assertEqual(s8["pgw_selection"],
                         {"method": None, "dns_resolvers": [], "apn_to_home_pgw": []})

    def test_interconnect_has_no_implicit_route_or_security_policy(self):
        interconnect = self.profile["s8"]["interconnect"]
        self.assertEqual(interconnect["peer_networks"], [])
        for field in ("local_interface", "security_policy", "routing_policy", "firewall_policy"):
            self.assertIsNone(interconnect[field])

    def test_candidate_realms_are_derived_but_not_operational(self):
        p = self.profile
        s6a = p["diameter"]["s6a"]
        for role, network in (("home", "home_network"), ("visited", "visited_network")):
            plmn = p[network]["plmn"]
            expected = "epc.mnc" + plmn["mnc"].zfill(3) + ".mcc" + plmn["mcc"] + ".3gppnetwork.org"
            self.assertEqual(s6a["candidate_" + role + "_realm"], expected)
        self.assertIs(s6a["candidate_realms_confirmed"], False)
        self.assertIsNone(s6a["origin_realm"])
        self.assertIsNone(s6a["destination_realm"])
        self.assertEqual(s6a["application_id"], 16777251)
        self.assertEqual(s6a["vendor_id"], 10415)
        self.assertEqual(s6a["local_function"], "MME")

    def test_diameter_cannot_connect_or_accept_unknown_peers(self):
        s6a = self.profile["diameter"]["s6a"]
        for field in ("enabled", "connect_peer", "accept_unknown_peers"):
            self.assertIs(s6a[field], False)
        self.assertEqual(s6a["realm_routes"], [])
        for field in ("origin_host", "destination_host", "peer_identity", "peer_address",
                      "peer_port", "transport", "security_policy"):
            self.assertIsNone(s6a[field])
