"""
speed_test.py  -  Network Speed Test
Tests download/upload/ping using HTTP requests — no external libs needed
"""
import urllib.request, time, threading, socket, logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Test servers (public files for download testing)
DOWNLOAD_URLS = [
    ("Cloudflare",  "https://speed.cloudflare.com/__down?bytes=10000000"),
    ("Google",      "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"),
    ("GitHub CDN",  "https://github.com/favicon.ico"),
]

PING_HOSTS = [
    ("Google DNS",    "8.8.8.8",     53),
    ("Cloudflare",    "1.1.1.1",     53),
    ("OpenDNS",       "208.67.222.222", 53),
]

def ping_host(host: str, port: int = 80, count: int = 4) -> dict:
    """TCP ping — measure latency."""
    times = []
    for _ in range(count):
        try:
            start = time.perf_counter()
            s = socket.create_connection((host, port), timeout=3)
            s.close()
            ms = (time.perf_counter() - start) * 1000
            times.append(ms)
        except Exception:
            pass
        time.sleep(0.2)
    if not times:
        return {"host": host, "min": None, "max": None, "avg": None, "loss": 100}
    return {
        "host": host,
        "min":  round(min(times), 1),
        "max":  round(max(times), 1),
        "avg":  round(sum(times)/len(times), 1),
        "loss": round((count - len(times)) / count * 100),
        "jitter": round(max(times) - min(times), 1) if len(times) > 1 else 0,
    }

def test_download_speed(url: str, timeout: int = 15) -> dict:
    """Measure download speed in Mbps."""
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "FYP-SpeedTest/8.0")
        start = time.perf_counter()
        bytes_received = 0
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk: break
                bytes_received += len(chunk)
                if time.perf_counter() - start > 10: break  # max 10s
        elapsed = time.perf_counter() - start
        if elapsed < 0.1 or bytes_received < 1000:
            return {"error": "Too fast / too small"}
        mbps = (bytes_received * 8) / (elapsed * 1_000_000)
        return {
            "bytes":   bytes_received,
            "elapsed": round(elapsed, 2),
            "mbps":    round(mbps, 2),
            "mb":      round(bytes_received / 1_000_000, 2),
        }
    except Exception as e:
        return {"error": str(e)}

class SpeedTester:
    def __init__(self, progress_callback=None):
        self.cb       = progress_callback
        self.results  = {}
        self.running  = False

    def _emit(self, msg):
        if self.cb: self.cb(msg)

    def run_full_test(self) -> dict:
        self.running = True
        self.results = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ping":      [],
            "download":  [],
            "summary":   {},
        }

        # Ping tests
        self._emit("[TEST] Running ping tests...")
        for name, host, port in PING_HOSTS:
            if not self.running: break
            self._emit(f"  Pinging {name} ({host})...")
            r = ping_host(host, port)
            r["name"] = name
            self.results["ping"].append(r)
            if r["avg"]:
                self._emit(f"  {name}: {r['avg']}ms avg  (min:{r['min']} max:{r['max']} loss:{r['loss']}%)")
            else:
                self._emit(f"  {name}: UNREACHABLE")

        # Download tests
        self._emit("\n[TEST] Running download speed tests...")
        speeds = []
        for name, url in DOWNLOAD_URLS:
            if not self.running: break
            self._emit(f"  Testing {name}...")
            r = test_download_speed(url)
            r["name"] = name
            self.results["download"].append(r)
            if "mbps" in r:
                self._emit(f"  {name}: {r['mbps']} Mbps  ({r['mb']} MB in {r['elapsed']}s)")
                speeds.append(r["mbps"])
            else:
                self._emit(f"  {name}: {r.get('error','Failed')}")

        # Summary
        pings = [r["avg"] for r in self.results["ping"] if r.get("avg")]
        self.results["summary"] = {
            "best_download_mbps": max(speeds) if speeds else 0,
            "avg_download_mbps":  round(sum(speeds)/len(speeds), 2) if speeds else 0,
            "best_ping_ms":       min(pings) if pings else None,
            "avg_ping_ms":        round(sum(pings)/len(pings), 1) if pings else None,
            "grade":              _grade_connection(max(speeds) if speeds else 0,
                                                    min(pings) if pings else 999),
        }
        self._emit(f"\n[RESULT] Best download: {self.results['summary']['best_download_mbps']} Mbps")
        self._emit(f"[RESULT] Best ping: {self.results['summary']['best_ping_ms']} ms")
        self._emit(f"[RESULT] Grade: {self.results['summary']['grade']}")
        self.running = False
        return self.results

    def stop(self): self.running = False

def _grade_connection(mbps: float, ping_ms: float) -> str:
    if mbps >= 100 and ping_ms < 20:  return "A+ EXCELLENT"
    if mbps >= 50  and ping_ms < 50:  return "A  VERY GOOD"
    if mbps >= 25  and ping_ms < 80:  return "B  GOOD"
    if mbps >= 10  and ping_ms < 150: return "C  AVERAGE"
    if mbps >= 1:                      return "D  SLOW"
    return "F  VERY SLOW"
