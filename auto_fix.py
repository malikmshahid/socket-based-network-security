"""
=============================================================================
auto_fix.py - Vulnerability Auto-Fix Engine
=============================================================================
AI-Powered Vulnerability Assessment System v5.0
Ek click se common security issues automatically fix karta hai
=============================================================================
"""

import subprocess
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

FIX_CATALOG = [
    {
        "id":          "fw_enable",
        "title":       "Enable Windows Firewall",
        "description": "Turns ON firewall for all profiles (Domain, Private, Public)",
        "severity":    "CRITICAL",
        "category":    "Firewall",
        "cmd":         ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
        "verify_cmd":  ["netsh", "advfirewall", "show", "allprofiles"],
        "verify_key":  "ON",
        "reversible":  True,
        "undo_cmd":    ["netsh", "advfirewall", "set", "allprofiles", "state", "off"],
    },
    {
        "id":          "block_rdp",
        "title":       "Block RDP Port 3389",
        "description": "Blocks Remote Desktop Protocol — prevents BlueKeep exploitation",
        "severity":    "CRITICAL",
        "category":    "Port Security",
        "cmd":         ["netsh", "advfirewall", "firewall", "add", "rule",
                        "name=FYP_Block_RDP", "protocol=TCP",
                        "dir=in", "localport=3389", "action=block"],
        "verify_cmd":  None,
        "reversible":  True,
        "undo_cmd":    ["netsh", "advfirewall", "firewall",
                        "delete", "rule", "name=FYP_Block_RDP"],
    },
    {
        "id":          "block_smb",
        "title":       "Block SMB Port 445",
        "description": "Blocks Server Message Block — prevents WannaCry/EternalBlue",
        "severity":    "CRITICAL",
        "category":    "Port Security",
        "cmd":         ["netsh", "advfirewall", "firewall", "add", "rule",
                        "name=FYP_Block_SMB", "protocol=TCP",
                        "dir=in", "localport=445", "action=block"],
        "reversible":  True,
        "undo_cmd":    ["netsh", "advfirewall", "firewall",
                        "delete", "rule", "name=FYP_Block_SMB"],
    },
    {
        "id":          "block_telnet",
        "title":       "Block Telnet Port 23",
        "description": "Blocks Telnet — plaintext credentials are highly insecure",
        "severity":    "HIGH",
        "category":    "Port Security",
        "cmd":         ["netsh", "advfirewall", "firewall", "add", "rule",
                        "name=FYP_Block_Telnet", "protocol=TCP",
                        "dir=in", "localport=23", "action=block"],
        "reversible":  True,
        "undo_cmd":    ["netsh", "advfirewall", "firewall",
                        "delete", "rule", "name=FYP_Block_Telnet"],
    },
    {
        "id":          "block_ftp",
        "title":       "Block FTP Port 21",
        "description": "Blocks FTP — unencrypted file transfer, vulnerable to sniffing",
        "severity":    "HIGH",
        "category":    "Port Security",
        "cmd":         ["netsh", "advfirewall", "firewall", "add", "rule",
                        "name=FYP_Block_FTP", "protocol=TCP",
                        "dir=in", "localport=21", "action=block"],
        "reversible":  True,
        "undo_cmd":    ["netsh", "advfirewall", "firewall",
                        "delete", "rule", "name=FYP_Block_FTP"],
    },
    {
        "id":          "pw_lockout",
        "title":       "Set Account Lockout Policy",
        "description": "Lock account after 5 failed attempts — prevents brute force",
        "severity":    "HIGH",
        "category":    "Password Policy",
        "cmd":         ["net", "accounts", "/lockoutthreshold:5",
                        "/lockoutduration:30"],
        "reversible":  False,
    },
    {
        "id":          "pw_minlen",
        "title":       "Enforce Minimum Password Length (12)",
        "description": "Require minimum 12-character passwords system-wide",
        "severity":    "MEDIUM",
        "category":    "Password Policy",
        "cmd":         ["net", "accounts", "/minpwlen:12"],
        "reversible":  False,
    },
    {
        "id":          "disable_rdp_svc",
        "title":       "Disable Remote Desktop Service",
        "description": "Stops and disables TermService to prevent RDP attacks",
        "severity":    "CRITICAL",
        "category":    "Services",
        "cmd":         ["sc", "config", "TermService", "start=disabled"],
        "reversible":  True,
        "undo_cmd":    ["sc", "config", "TermService", "start=auto"],
    },
    {
        "id":          "disable_print_spooler",
        "title":       "Disable Print Spooler (PrintNightmare fix)",
        "description": "Stops Print Spooler service — fixes CVE-2021-34527",
        "severity":    "CRITICAL",
        "category":    "Services",
        "cmd":         ["sc", "stop", "Spooler"],
        "reversible":  True,
        "undo_cmd":    ["sc", "start", "Spooler"],
    },
    {
        "id":          "flush_dns",
        "title":       "Flush DNS Cache",
        "description": "Clears DNS cache — removes potential DNS poisoning entries",
        "severity":    "LOW",
        "category":    "Network",
        "cmd":         ["ipconfig", "/flushdns"],
        "reversible":  False,
    },
]


class AutoFixer:
    """
    Applies security fixes automatically.
    Tracks what was fixed and supports undo.
    """

    def __init__(self):
        self.fix_log = []   # Log of applied fixes

    def _run(self, cmd: list) -> tuple:
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=15, creationflags=flags)
            return r.returncode == 0, r.stdout + r.stderr
        except Exception as e:
            return False, str(e)

    def apply_fix(self, fix_id: str,
                  progress_cb=None) -> tuple:
        """Apply a single fix by ID."""
        fix = next((f for f in FIX_CATALOG if f["id"] == fix_id), None)
        if not fix:
            return False, f"Fix '{fix_id}' not found"

        if progress_cb:
            progress_cb(f"Applying: {fix['title']}...")

        ok, out = self._run(fix["cmd"])

        entry = {
            "id":        fix_id,
            "title":     fix["title"],
            "success":   ok,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "output":    out[:200],
        }
        self.fix_log.append(entry)

        msg = f"✓ {fix['title']}" if ok else f"✗ {fix['title']}: {out[:100]}"
        return ok, msg

    def apply_all_critical(self, progress_cb=None) -> list:
        """Apply all CRITICAL severity fixes."""
        results = []
        critical = [f for f in FIX_CATALOG if f["severity"] == "CRITICAL"]
        for fix in critical:
            ok, msg = self.apply_fix(fix["id"], progress_cb)
            results.append((fix["id"], ok, msg))
        return results

    def apply_recommended(self, progress_cb=None) -> list:
        """Apply all CRITICAL + HIGH fixes."""
        results = []
        targets = [f for f in FIX_CATALOG
                   if f["severity"] in ("CRITICAL", "HIGH")]
        for fix in targets:
            ok, msg = self.apply_fix(fix["id"], progress_cb)
            results.append((fix["id"], ok, msg))
        return results

    def undo_fix(self, fix_id: str) -> tuple:
        """Undo a reversible fix."""
        fix = next((f for f in FIX_CATALOG if f["id"] == fix_id), None)
        if not fix:
            return False, "Fix not found"
        if not fix.get("reversible"):
            return False, "This fix cannot be undone"
        ok, out = self._run(fix["undo_cmd"])
        return ok, "Undone successfully!" if ok else out

    def get_catalog(self) -> list:
        return FIX_CATALOG

    def get_log(self) -> list:
        return self.fix_log
