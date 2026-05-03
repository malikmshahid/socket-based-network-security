"""
=============================================================================
scan_history.py - Scan History Manager
=============================================================================
AI-Powered Vulnerability Assessment System v4.0
Saves/loads scan results to/from local JSON database
=============================================================================
"""

import json
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

HISTORY_FILE = "scan_history.json"
MAX_HISTORY  = 50   # Maximum scans to keep


class ScanHistory:
    """
    Manages persistent scan history stored in a local JSON file.
    Saves scan results and risk assessments for later review.
    """

    def __init__(self):
        self.history = self._load()

    def _load(self) -> list:
        """Load history from file."""
        if not os.path.exists(HISTORY_FILE):
            return []
        try:
            with open(HISTORY_FILE, "r") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            logger.error(f"History load error: {e}")
            return []

    def _save(self):
        """Save history to file."""
        try:
            with open(HISTORY_FILE, "w") as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            logger.error(f"History save error: {e}")

    def add_entry(self, scan_results: dict, risk_result: dict):
        """
        Add a new scan entry to history.

        Args:
            scan_results: Output from VulnerabilityScanner
            risk_result:  Output from RiskAssessmentEngine
        """
        entry = {
            "id":           len(self.history) + 1,
            "timestamp":    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "target_ip":    scan_results.get("target_ip", "Unknown"),
            "risk_score":   risk_result.get("risk_score", 0),
            "risk_level":   risk_result.get("risk_level", "LOW"),
            "open_ports":   scan_results.get("open_ports", []),
            "critical_ports": scan_results.get("critical_ports_open", []),
            "firewall":     scan_results.get("firewall_status", "Unknown"),
            "antivirus":    scan_results.get("antivirus_status", "Unknown"),
            "os_updates":   scan_results.get("os_update_status", "Unknown"),
            "hostname":     scan_results.get("system_info", {}).get("hostname", "Unknown"),
            "threats_count": len(risk_result.get("threats", [])),
            "recs_count":   len(risk_result.get("recommendations", [])),
        }

        self.history.insert(0, entry)   # Newest first

        # Trim to max
        if len(self.history) > MAX_HISTORY:
            self.history = self.history[:MAX_HISTORY]

        self._save()
        logger.info(f"Scan history saved: #{entry['id']} {entry['target_ip']}")
        return entry

    def get_all(self) -> list:
        """Return all history entries."""
        return self.history

    def get_recent(self, n=10) -> list:
        """Return n most recent entries."""
        return self.history[:n]

    def clear(self):
        """Clear all history."""
        self.history = []
        self._save()

    def get_stats(self) -> dict:
        """Return summary statistics across all scans."""
        if not self.history:
            return {}

        scores   = [e["risk_score"] for e in self.history]
        critical = sum(1 for e in self.history if e["risk_level"] == "CRITICAL")
        high     = sum(1 for e in self.history if e["risk_level"] == "HIGH")

        return {
            "total_scans":   len(self.history),
            "avg_score":     round(sum(scores) / len(scores), 1),
            "max_score":     max(scores),
            "min_score":     min(scores),
            "critical_count": critical,
            "high_count":    high,
            "last_scan":     self.history[0]["timestamp"] if self.history else "Never",
        }
