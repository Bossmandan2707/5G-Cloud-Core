import struct
import tempfile
import unittest
from pathlib import Path

from ims.trace_call import combine


class CallTraceTests(unittest.TestCase):
    def pcap(self, path, second, payload):
        path.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 276)
                         + struct.pack("<IIII", second, 0, len(payload), len(payload))
                         + payload)

    def test_combined_trace_preserves_points_and_timestamp_order(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.pcap(root / "sip", 20, b"sip")
            self.pcap(root / "nas", 10, b"ngap")
            output = root / "combined"
            count = combine([("sip", [root / "sip"]), ("n2", [root / "nas"])], output)
            data = output.read_bytes()
            offset, interfaces, packets = 0, [], []
            while offset < len(data):
                kind, size = struct.unpack("<II", data[offset:offset + 8])
                self.assertEqual(size, struct.unpack("<I", data[offset + size - 4:offset + size])[0])
                body = data[offset + 8:offset + size - 4]
                if kind == 1:
                    interfaces.append(body)
                elif kind == 6:
                    packets.append(struct.unpack("<IIIII", body[:20]))
                offset += size
            self.assertEqual(count, 2)
            self.assertEqual(len(interfaces), 2)
            self.assertEqual([p[0] for p in packets], [1, 0])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_truncated_packet_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad"
            self.pcap(path, 1, b"test")
            path.write_bytes(path.read_bytes()[:-1])
            with self.assertRaises(ValueError):
                combine([("n2", [path])], Path(folder) / "out")
