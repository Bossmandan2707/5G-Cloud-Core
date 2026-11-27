"""Passive N2 monitor with optional sanitized NGAP message decoding; never reconnects the UE."""
import argparse
import shutil
import signal
import time
from pathlib import Path

from ngap_trace import NgapBuffer, NgapCapture
from ngap_decode import DecoderBuffer, NgapDecoder


def duration(value):
    value = int(value)
    if not 0 <= value <= 86400:
        raise argparse.ArgumentTypeError("seconds must be 0..86400 (0 = until Ctrl+C)")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seconds", type=duration, nargs="?", default=0)
    parser.add_argument("--decode", action="store_true", help="SIP-debug-style decoded NGAP signaling, excluding NAS bodies")
    args = parser.parse_args()
    podman = shutil.which("podman")
    if not podman and Path("/opt/podman/bin/podman").is_file():
        podman = "/opt/podman/bin/podman"
    buffer = DecoderBuffer() if args.decode else NgapBuffer()
    capture = NgapDecoder(podman, buffer) if args.decode else NgapCapture(podman, buffer)
    started, last_id, previous_status = time.monotonic(), 0, None
    interrupted = False

    def terminate(_signum, _frame):
        raise KeyboardInterrupt

    previous_handler = signal.signal(signal.SIGTERM, terminate)
    print("Decoded NGAP signaling · passive gNB ↔ AMF · no NAS bodies or security keys"
          if args.decode else "NGAP transport monitor · passive N2 SCTP · no decoded NGAP procedures", flush=True)
    print("UL = gNB → AMF; DL = AMF → gNB. Context IDs are not subscriber identities."
          if args.decode else "UL = gNB → AMF; DL = AMF → gNB. Frame sizes include Ethernet headers.", flush=True)
    try:
        capture.start()
        while not args.seconds or time.monotonic() - started < args.seconds:
            data = buffer.snapshot()
            if data["status"] != previous_status:
                print(data["status"].upper() + ": " + data["message"], flush=True)
                previous_status = data["status"]
            for packet in data["events"] if args.decode else data["packets"]:
                if packet["id"] > last_id:
                    if args.decode:
                        arrow = {"UL": "gNB ---> AMF", "DL": "gNB <--- AMF"}.get(packet["direction"], "OTHER endpoints")
                        print(f'\n{packet["timestamp"]:.6f}  {arrow}  {packet["message"]}\n'
                              f'  {packet["outcome"]} · procedure {packet["procedure_code"]}'
                              f' · criticality {packet["criticality"]}'
                              f' · stream {packet["stream"]} · RAN context {packet["ran_context_id"]}'
                              f' · AMF context {packet["amf_context_id"]}\n'
                              f'  Causes: {packet["causes"]}', flush=True)
                    else:
                        print(f'{packet["timestamp"]:.6f} {packet["direction"]:5} '
                              f'{packet["source"]}:{packet["source_port"]} → '
                              f'{packet["destination"]}:{packet["destination_port"]} '
                              f'{packet["bytes"]} frame bytes', flush=True)
                    last_id = packet["id"]
            if not args.decode:
                print(f'5s average: UL {data["rates"]["UL"]["pps"]:.1f} pkt/s · '
                      f'DL {data["rates"]["DL"]["pps"]:.1f} pkt/s', flush=True)
            if data["status"] == "error":
                return 2
            time.sleep(1)
    except KeyboardInterrupt:
        interrupted = True
    finally:
        capture.close()
        signal.signal(signal.SIGTERM, previous_handler)
        data = buffer.snapshot()
        if args.decode:
            print(f'Stopped. Decoded {data["total_events"]} NGAP messages; '
                  f'rejected records: {data["rejected_records"]}.', flush=True)
        else:
            print("Stopped. Captured: " + " · ".join(
                f'{d} {data["totals"].get(d + "_packets", 0)} packets' for d in ("UL", "DL", "OTHER")),
                flush=True)
    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
