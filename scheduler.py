"""
=============================================================================
scheduler.py - Scheduled Auto-Scan System
=============================================================================
AI-Powered Vulnerability Assessment System v5.0
Daily/weekly automatic scans — runs in background
=============================================================================
"""

import threading
import json
import os
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

SCHEDULE_FILE = "scan_schedule.json"


class ScanScheduler:
    """
    Manages scheduled automatic scans.
    Saves schedule config to file — persists across restarts.
    """

    def __init__(self, scan_callback=None):
        """
        Args:
            scan_callback: Function(target_ip) to call when scan is due
        """
        self.callback  = scan_callback
        self.running   = False
        self._thread   = None
        self.config    = self._load()

    def _load(self) -> dict:
        if not os.path.exists(SCHEDULE_FILE):
            return {
                "enabled":    False,
                "frequency":  "daily",    # daily / weekly
                "time":       "02:00",    # HH:MM
                "target_ip":  "127.0.0.1",
                "last_run":   None,
                "next_run":   None,
                "run_count":  0,
            }
        try:
            with open(SCHEDULE_FILE) as f:
                return json.load(f)
        except Exception:
            return self._load.__func__(self)

    def _save(self):
        try:
            with open(SCHEDULE_FILE, "w") as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Schedule save error: {e}")

    def update(self, enabled: bool, frequency: str,
               scan_time: str, target_ip: str):
        """Update schedule settings."""
        self.config["enabled"]   = enabled
        self.config["frequency"] = frequency
        self.config["time"]      = scan_time
        self.config["target_ip"] = target_ip
        self.config["next_run"]  = self._calc_next_run()
        self._save()
        logger.info(f"Schedule updated: {frequency} at {scan_time} — {'ON' if enabled else 'OFF'}")

    def _calc_next_run(self) -> str:
        """Calculate next run datetime string."""
        try:
            now  = datetime.now()
            h, m = map(int, self.config["time"].split(":"))
            next_dt = now.replace(hour=h, minute=m, second=0, microsecond=0)

            if next_dt <= now:
                if self.config["frequency"] == "daily":
                    next_dt += timedelta(days=1)
                else:
                    next_dt += timedelta(weeks=1)

            return next_dt.strftime("%Y-%m-%d %H:%M")
        except Exception:
            return "Unknown"

    def start(self):
        """Start background scheduler thread."""
        self.running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        """Check every minute if a scan is due."""
        import time
        while self.running:
            try:
                if self.config.get("enabled") and self.config.get("next_run"):
                    now_str = datetime.now().strftime("%Y-%m-%d %H:%M")
                    if now_str >= self.config["next_run"]:
                        self._run_scheduled_scan()
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
            time.sleep(30)  # Check every 30 seconds

    def _run_scheduled_scan(self):
        """Execute the scheduled scan."""
        logger.info(f"Running scheduled scan: {self.config['target_ip']}")

        self.config["last_run"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.config["run_count"] = self.config.get("run_count", 0) + 1
        self.config["next_run"]  = self._calc_next_run()
        self._save()

        if self.callback:
            try:
                self.callback(self.config["target_ip"])
            except Exception as e:
                logger.error(f"Scheduled scan error: {e}")

    def get_config(self) -> dict:
        return self.config.copy()

    def get_status_text(self) -> str:
        if not self.config.get("enabled"):
            return "Scheduled scanning: DISABLED"
        return (
            f"Next scan: {self.config.get('next_run','--')}  |  "
            f"Frequency: {self.config.get('frequency','--').upper()}  |  "
            f"Target: {self.config.get('target_ip','--')}  |  "
            f"Total runs: {self.config.get('run_count',0)}"
        )
