"""Small Python monitoring exporter.

Exposes Prometheus metrics on :8000/metrics:
  - host CPU / memory / disk / load average (via psutil)
  - optional HTTP endpoint probes (up + latency) for every URL in $TARGETS

Example: TARGETS="http://open5gs-nrf:7777,http://example.com" python app.py
"""
import os
import time
import urllib.request

import psutil
from prometheus_client import Gauge, Info, start_http_server

LAB_NAME = "Dan Powell Technologies"
lab = Info("lab", "Lab identity")
lab.info({"name": LAB_NAME})

PORT = int(os.getenv("PORT", "8000"))
INTERVAL = float(os.getenv("INTERVAL_SECONDS", "5"))
TIMEOUT = float(os.getenv("PROBE_TIMEOUT_SECONDS", "3"))
TARGETS = [t.strip() for t in os.getenv("TARGETS", "").split(",") if t.strip()]

cpu = Gauge("host_cpu_percent", "Host CPU utilisation percent")
mem = Gauge("host_memory_percent", "Host memory utilisation percent")
disk = Gauge("host_disk_percent", "Root filesystem utilisation percent")
load1 = Gauge("host_load1", "1-minute load average")
probe_up = Gauge("probe_up", "1 if the target answered with HTTP < 500", ["target"])
probe_latency = Gauge("probe_latency_seconds", "Probe round-trip time", ["target"])


def probe(target: str) -> None:
    start = time.monotonic()
    try:
        with urllib.request.urlopen(target, timeout=TIMEOUT) as resp:
            ok = resp.status < 500
    except urllib.error.HTTPError as err:  # server answered, just not 2xx
        ok = err.code < 500
    except Exception:
        ok = False
    probe_up.labels(target).set(1 if ok else 0)
    probe_latency.labels(target).set(time.monotonic() - start)


def collect() -> float:
    cpu_percent = psutil.cpu_percent(interval=None)
    cpu.set(cpu_percent)
    mem.set(psutil.virtual_memory().percent)
    disk.set(psutil.disk_usage("/").percent)
    load1.set(os.getloadavg()[0])
    for target in TARGETS:
        probe(target)
    return cpu_percent


if __name__ == "__main__":
    start_http_server(PORT)
    print(f"{LAB_NAME} exporter listening on :{PORT}, probing {TARGETS or 'nothing'}", flush=True)
    while True:
        collect()
        time.sleep(INTERVAL)
