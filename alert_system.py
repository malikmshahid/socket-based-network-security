"""
=============================================================================
alert_system.py - Real-Time Threat Alert System
=============================================================================
AI-Powered Vulnerability Assessment System v5.0
Background monitoring — popup alerts jab koi threat detect ho
=============================================================================
"""

import threading
import subprocess
import socket
import os
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

CRITICAL_PORTS = [21, 22, 23, 25, 135, 139, 445, 3389, 5900]
ALERT_INTERVAL = 30   # seconds between checks


class AlertSystem:
    """
    Background thread that monitors for new threats and fires callbacks.
    Checks: new open ports, firewall status, suspicious connections.
    """

    def __init__(self, alert_callback=None, interval=ALERT_INTERVAL):
        self.callback  = alert_callback
        self.interval  = interval
        self.running   = False
        self._thread   = None
        self._prev_ports  = set()
        self._prev_fw     = "ON"
        self.alert_log    = []
        self.enabled      = True

    def start(self):
        self.running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True)
        self._thread.start()
        logger.info("AlertSystem started")

    def stop(self):
        self.running = False

    def _fire(self, severity: str, title: str, message: str):
        """Fire an alert to the callback."""
        entry = {
            "severity":  severity,
            "title":     title,
            "message":   message,
            "time":      datetime.now().strftime("%H:%M:%S"),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        self.alert_log.insert(0, entry)
        if len(self.alert_log) > 100:
            self.alert_log = self.alert_log[:100]

        if self.callback and self.enabled:
            try:
                self.callback(entry)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")

    def _check_ports(self):
        """Check if any new critical ports have opened."""
        open_now = set()
        for port in CRITICAL_PORTS:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                result = s.connect_ex(("127.0.0.1", port))
                s.close()
                if result == 0:
                    open_now.add(port)
            except Exception:
                pass

        new_open = open_now - self._prev_ports
        for port in new_open:
            self._fire(
                "CRITICAL",
                f"⚠ New Port Opened: {port}",
                f"Port {port} just became OPEN on your system!\n"
                f"This is a CRITICAL security event.\n"
                f"Port {port} is commonly used for attacks."
            )
        self._prev_ports = open_now

    def _check_firewall(self):
        """Check if firewall was turned off."""
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            r = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True, text=True, timeout=5,
                creationflags=flags
            )
            if "OFF" in r.stdout.upper():
                if self._prev_fw == "ON":
                    self._fire(
                        "CRITICAL",
                        "🔴 FIREWALL DISABLED!",
                        "Windows Firewall has been turned OFF!\n"
                        "Your system is now EXPOSED to network attacks.\n"
                        "Re-enable firewall immediately!"
                    )
                    self._prev_fw = "OFF"
            else:
                self._prev_fw = "ON"
        except Exception:
            pass

    def _check_connections(self):
        """Check for suspicious outbound connections."""
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            r = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, timeout=5,
                creationflags=flags
            )
            suspicious_ports = [4444, 1337, 31337, 6666, 9999]
            for line in r.stdout.splitlines():
                for sp in suspicious_ports:
                    if f":{sp} " in line and "ESTABLISHED" in line:
                        self._fire(
                            "HIGH",
                            f"⚠ Suspicious Connection: Port {sp}",
                            f"Active connection detected on port {sp}!\n"
                            f"This port is commonly used by malware/backdoors.\n"
                            f"Connection details: {line.strip()[:100]}"
                        )
        except Exception:
            pass

    def _loop(self):
        """Background monitoring loop."""
        # Initial baseline
        time.sleep(3)
        self._check_ports()

        while self.running:
            try:
                self._check_firewall()
                self._check_ports()
                self._check_connections()
            except Exception as e:
                logger.error(f"Alert loop error: {e}")
            time.sleep(self.interval)

    def manual_check(self):
        """Run an immediate check (called from UI)."""
        threading.Thread(target=self._run_manual, daemon=True).start()

    def _run_manual(self):
        self._check_firewall()
        self._check_ports()
        self._check_connections()
        self._fire("INFO", "✓ Manual Check Complete",
                   "Real-time check completed — no new threats detected.")

    def get_log(self) -> list:
        return self.alert_log

    def clear_log(self):
        self.alert_log = []
