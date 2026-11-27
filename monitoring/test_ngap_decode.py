import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import unittest
from unittest.mock import patch
import uuid
import xml.etree.ElementTree as ET


SPEC = importlib.util.spec_from_file_location(
    "ngap_helper_decoder", Path(__file__).resolve().parent.parent / "tools/ngap-decode/decoder.py")
decoder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(decoder)


def synthetic_pcap(pdus=(bytes.fromhex("00094003000000"),), fragmented=False):
    """Synthetic ErrorIndication PDUs with no NAS, UE identity or security IEs."""
    groups = [[(3, index, pdu) for index, pdu in enumerate(pdus)]]
    if fragmented:
        groups = [[(2, 0, pdus[0][:3])], [(1, 0, pdus[0][3:])]]
    pcap = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    tsn = 0
    for index, group in enumerate(groups):
        chunks = b""
        for flags, sequence, pdu in group:
            tsn += 1
            chunk = struct.pack("!BBHIHHI", 0, flags, 16 + len(pdu), tsn, 0, sequence, 60) + pdu
            chunks += chunk + b"\0" * (-len(chunk) % 4)
        sctp = struct.pack("!HHII", 39645, 38412, 1, 0) + chunks
        crc = 0xffffffff
        for byte in sctp:
            crc ^= byte
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
        sctp = sctp[:8] + struct.pack("<I", crc ^ 0xffffffff) + sctp[12:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(sctp), index + 1, 0, 64, 132, 0,
                         socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.5"))
        checksum = sum(struct.unpack("!10H", ip))
        checksum = (checksum & 65535) + (checksum >> 16)
        checksum = (checksum & 65535) + (checksum >> 16)
        ip = ip[:10] + struct.pack("!H", ~checksum & 65535) + ip[12:]
        frame = b"\0" * 12 + b"\x08\x00" + ip + sctp
        pcap += struct.pack("<IIII", 1795160801, 123456 + index, len(frame), len(frame)) + frame
    return pcap


def pdml(procedure=21, outcome=0, message="NGSetupRequest", extra=""):
    return ET.fromstring(f"""<packet>
      <proto name="frame"><field name="frame.time_epoch" show="1795160801.123456"/>
        <field name="frame.len" show="106"/></proto>
      <proto name="ip"><field name="ip.src" show="127.0.0.1"/>
        <field name="ip.dst" show="127.0.0.5"/></proto>
      <proto name="sctp"><field name="sctp.srcport" show="39645"/>
        <field name="sctp.dstport" show="38412"/><field name="sctp.data_sid" show="0"/></proto>
      <proto name="ngap"><field name="ngap.NGAP_PDU" show="{outcome}">
        <field name="ngap.procedureCode" show="{procedure}"/>
        <field name="ngap.criticality" show="0"/>
        <field name="ngap.{message}_element" show=""/>
        {extra}</field></proto></packet>""")


class SanitizerTests(unittest.TestCase):
    def test_ie_criticalities_and_diagnostics_do_not_override_pdu_header(self):
        packet = pdml(extra='<field name="ngap.protocolIEs">'
                            '<field name="ngap.criticality" show="2"/>'
                            '<field name="ngap.procedureCode" show="9"/></field>')
        event = decoder.decode_packet(packet)[0]
        self.assertEqual(event["procedure_code"], 21)
        self.assertEqual(event["criticality"], 0)

    def test_message_names_and_outcomes(self):
        for code, names in decoder.MESSAGES.items():
            for outcome, name in enumerate(names):
                event = decoder.decode_packet(pdml(code, outcome, name))[0]
                self.assertEqual(event["message"], name)
                self.assertEqual(event["outcome"], decoder.OUTCOMES[outcome])

    def test_sensitive_and_generic_text_never_exported(self):
        packet = pdml(extra='<field name="ngap.NAS_PDU" show="PRIVATE_NAS"/>'
                            '<field name="ngap.SecurityKey" show="PRIVATE_KEY"/>'
                            '<field name="nas_5gs.mobileidentity" show="PRIVATE_ID"/>'
                            '<field name="_ws.col.Info" show="PRIVATE_INFO"/>')
        output = json.dumps(decoder.decode_packet(packet))
        self.assertNotIn("PRIVATE", output)
        self.assertNotIn("SecurityKey", output)

    def test_unknown_and_mismatched_messages(self):
        self.assertEqual(decoder.decode_packet(pdml(255, 0, "FutureMessage"))[0]["message"],
                         "Unknown NGAP procedure")
        with self.assertRaises(ValueError):
            decoder.decode_packet(pdml(21, 0, "InitialUEMessage"))

    def test_bundled_pdus_remain_distinct(self):
        packet = pdml()
        packet.append(pdml(21, 1, "NGSetupResponse").find("proto[@name='ngap']"))
        events = decoder.decode_packet(packet)
        self.assertEqual([e["message"] for e in events], ["NGSetupRequest", "NGSetupResponse"])
        self.assertEqual([e["pdu_index"] for e in events], [0, 1])

    def test_ambiguous_scalar_and_malformed_packets_rejected(self):
        for packet in (pdml(extra='<field name="ngap.procedureCode" show="15"/>'),
                       pdml(extra='<field name="_ws.malformed"/>')):
            with self.assertRaises(ValueError):
                decoder.decode_packet(packet)

    def test_context_and_numeric_causes_only(self):
        event = decoder.decode_packet(pdml(
            extra='<field name="ngap.RAN_UE_NGAP_ID" show="12"/>'
                  '<field name="ngap.AMF_UE_NGAP_ID" show="34"/>'
                  '<field name="ngap.radioNetwork" show="20" showname="PRIVATE"/>'))[0]
        self.assertEqual(event["ran_context_id"], 12)
        self.assertEqual(event["amf_context_id"], 34)
        self.assertEqual(event["causes"], [{"category": "radioNetwork", "value": 20}])

    def test_truncated_and_oversized_output_is_reported(self):
        for raw in (b"<packet>\n<proto", b"<packet>\n" + b"x" * 100 + b"\n</packet>\n"):
            with patch.object(decoder, "MAX_PACKET_XML", 32), patch.object(decoder, "emit") as emit:
                decoder.read_pdml(io.BytesIO(raw))
            self.assertEqual(emit.call_args.args[0]["type"], "warning")


@unittest.skipUnless(os.environ.get("NGAP_DECODER_INTEGRATION") == "1",
                     "Set NGAP_DECODER_INTEGRATION=1 after building ngap-decode:0.1")
class TsharkIntegrationTests(unittest.TestCase):
    def test_actual_offline_decode_and_bundled_pdus(self):
        for count, fragmented in ((1, False), (2, False), (1, True)):
            name = "dpt-ngap-fixture-" + uuid.uuid4().hex[:10]
            try:
                result = subprocess.run(
                    ["podman", "run", "--rm", "--name", name, "-i", "--network", "none",
                     "--cap-drop", "ALL", "localhost/ngap-decode:0.1",
                     "python3", "/decoder.py", "--stdin"],
                    input=synthetic_pcap((bytes.fromhex("00094003000000"),) * count, fragmented),
                    capture_output=True, timeout=30, check=True)
                records = [json.loads(line) for line in result.stdout.splitlines()]
                events = [r["event"] for r in records if r["type"] == "event"]
                self.assertEqual(len(events), count, records)
                self.assertTrue(all(e["message"] == "ErrorIndication" for e in events))
            finally:
                subprocess.run(["podman", "rm", "-f", name], capture_output=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
