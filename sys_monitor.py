"""
=============================================================================
sys_monitor.py - System Performance Monitor
=============================================================================
AI-Powered Vulnerability Assessment System v4.0
Real-time CPU, RAM, Disk, Network monitoring using psutil
=============================================================================
"""

import threading
import time
import logging

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed. Run: pip install psutil")


class SystemMonitor:
    """
    Continuously collects system performance metrics.
    Runs in background thread, provides latest readings on demand.
    """

    def __init__(self, interval=1.0):
        """
        Args:
            interval: Update interval in seconds (default 1s)
        """
        self.interval = interval
        self.running  = False
        self._thread  = None
        self.callbacks = []  # Functions called on each update

        # Latest readings
        self.data = {
            "cpu_percent":     0.0,
            "cpu_cores":       0,
            "cpu_freq_mhz":    0,
            "ram_percent":     0.0,
            "ram_used_gb":     0.0,
            "ram_total_gb":    0.0,
            "disk_percent":    0.0,
            "disk_used_gb":    0.0,
            "disk_total_gb":   0.0,
            "net_sent_mb":     0.0,
            "net_recv_mb":     0.0,
            "net_sent_speed":  0.0,   # MB/s
            "net_recv_speed":  0.0,
            "processes":       0,
            "boot_time":       "",
            "available":       PSUTIL_AVAILABLE,
        }
        self._prev_net_sent = 0
        self._prev_net_recv = 0

    def start(self):
        """Start background monitoring thread."""
        if not PSUTIL_AVAILABLE:
            logger.warning("psutil not available — monitoring disabled")
            return
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info("SystemMonitor started")

    def stop(self):
        """Stop monitoring thread."""
        self.running = False

    def add_callback(self, fn):
        """Register function to call on each data update."""
        self.callbacks.append(fn)

    def _loop(self):
        """Background update loop."""
        while self.running:
            try:
                self._update()
                for cb in self.callbacks:
                    try:
                        cb(self.data.copy())
                    except Exception:
                        pass
            except Exception as e:
                logger.error(f"Monitor error: {e}")
            time.sleep(self.interval)

    def _update(self):
        """Collect all metrics."""
        if not PSUTIL_AVAILABLE:
            return

        # CPU
        self.data["cpu_percent"]  = psutil.cpu_percent(interval=None)
        self.data["cpu_cores"]    = psutil.cpu_count(logical=True)
        try:
            freq = psutil.cpu_freq()
            self.data["cpu_freq_mhz"] = int(freq.current) if freq else 0
        except Exception:
            self.data["cpu_freq_mhz"] = 0

        # RAM
        mem = psutil.virtual_memory()
        self.data["ram_percent"]  = mem.percent
        self.data["ram_used_gb"]  = round(mem.used / (1024**3), 1)
        self.data["ram_total_gb"] = round(mem.total / (1024**3), 1)

        # Disk (C: on Windows)
        try:
            disk = psutil.disk_usage("C:\\" if __import__("os").name == "nt" else "/")
            self.data["disk_percent"]  = disk.percent
            self.data["disk_used_gb"]  = round(disk.used / (1024**3), 1)
            self.data["disk_total_gb"] = round(disk.total / (1024**3), 1)
        except Exception:
            pass

        # Network
        net = psutil.net_io_counters()
        sent_mb = round(net.bytes_sent / (1024**2), 1)
        recv_mb = round(net.bytes_recv / (1024**2), 1)

        # Speed (MB/s)
        self.data["net_sent_speed"] = round(
            max(0, sent_mb - self.data["net_sent_mb"]) / self.interval, 2)
        self.data["net_recv_speed"] = round(
            max(0, recv_mb - self.data["net_recv_mb"]) / self.interval, 2)

        self.data["net_sent_mb"] = sent_mb
        self.data["net_recv_mb"] = recv_mb

        # Processes
        self.data["processes"] = len(psutil.pids())

        # Boot time
        try:
            import datetime
            bt = psutil.boot_time()
            self.data["boot_time"] = datetime.datetime.fromtimestamp(bt).strftime("%Y-%m-%d %H:%M")
        except Exception:
            self.data["boot_time"] = "Unknown"

    def get_snapshot(self) -> dict:
        """Get latest data snapshot."""
        if PSUTIL_AVAILABLE:
            self._update()
        return self.data.copy()
