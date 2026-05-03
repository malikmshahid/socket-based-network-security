"""
=============================================================================
firewall_manager.py - Windows Firewall Rules Manager
=============================================================================
AI-Powered Vulnerability Assessment System v5.0
GUI se Windows Firewall rules add, delete, enable/disable karo
=============================================================================
"""

import subprocess
import os
import logging
import re

logger = logging.getLogger(__name__)


class FirewallManager:
    """Manage Windows Firewall rules via netsh commands."""

    def _run(self, cmd: list) -> tuple:
        """Run a netsh command. Returns (success, output)."""
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
                creationflags=flags
            )
            output = result.stdout + result.stderr
            success = result.returncode == 0
            return success, output
        except Exception as e:
            return False, str(e)

    def get_all_rules(self) -> list:
        """
        Fetch all firewall rules.
        Returns list of dicts: {name, direction, action, protocol, port, enabled}
        """
        ok, output = self._run([
            "netsh", "advfirewall", "firewall", "show", "rule", "name=all"
        ])
        if not ok:
            return []

        rules = []
        current = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Rule Name:"):
                if current:
                    rules.append(current)
                current = {"name": line.split(":", 1)[1].strip(),
                           "direction": "--", "action": "--",
                           "protocol": "--", "port": "--",
                           "enabled": "--", "profile": "--"}
            elif ":" in line and current:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                val = val.strip()
                if "direction"   in key: current["direction"] = val
                elif "action"    in key: current["action"]    = val
                elif "protocol"  in key: current["protocol"]  = val
                elif "localport" in key: current["port"]      = val
                elif "enabled"   in key: current["enabled"]   = val
                elif "profiles"  in key: current["profile"]   = val

        if current:
            rules.append(current)

        # Filter out empty/system entries
        return [r for r in rules if r.get("name") and r["name"] != "--"]

    def add_block_rule(self, name: str, port: str,
                        protocol: str = "TCP",
                        direction: str = "in") -> tuple:
        """Block a specific port."""
        if not name or not port:
            return False, "Name and port are required"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            f"protocol={protocol}",
            f"dir={direction}",
            f"localport={port}",
            "action=block"
        ]
        ok, out = self._run(cmd)
        msg = "Rule added successfully!" if ok else f"Failed: {out}"
        return ok, msg

    def add_allow_rule(self, name: str, port: str,
                        protocol: str = "TCP",
                        direction: str = "in") -> tuple:
        """Allow a specific port."""
        if not name or not port:
            return False, "Name and port are required"
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}",
            f"protocol={protocol}",
            f"dir={direction}",
            f"localport={port}",
            "action=allow"
        ]
        ok, out = self._run(cmd)
        msg = "Rule added successfully!" if ok else f"Failed: {out}"
        return ok, msg

    def delete_rule(self, name: str) -> tuple:
        """Delete a firewall rule by name."""
        cmd = ["netsh", "advfirewall", "firewall",
               "delete", "rule", f"name={name}"]
        ok, out = self._run(cmd)
        msg = "Rule deleted!" if ok else f"Failed: {out}"
        return ok, msg

    def enable_rule(self, name: str) -> tuple:
        cmd = ["netsh", "advfirewall", "firewall", "set", "rule",
               f"name={name}", "new", "enable=yes"]
        ok, out = self._run(cmd)
        return ok, "Enabled!" if ok else out

    def disable_rule(self, name: str) -> tuple:
        cmd = ["netsh", "advfirewall", "firewall", "set", "rule",
               f"name={name}", "new", "enable=no"]
        ok, out = self._run(cmd)
        return ok, "Disabled!" if ok else out

    def get_firewall_status(self) -> dict:
        """Get firewall ON/OFF status for all profiles."""
        ok, out = self._run([
            "netsh", "advfirewall", "show", "allprofiles", "state"
        ])
        status = {"domain": "Unknown", "private": "Unknown", "public": "Unknown"}
        if ok:
            for line in out.splitlines():
                line = line.strip().lower()
                if "domain" in line and "state" in line:
                    status["domain"] = "ON" if "on" in line else "OFF"
                elif "private" in line and "state" in line:
                    status["private"] = "ON" if "on" in line else "OFF"
                elif "public" in line and "state" in line:
                    status["public"] = "ON" if "on" in line else "OFF"
        return status

    def set_firewall_all(self, state: str) -> tuple:
        """Turn all firewall profiles ON or OFF."""
        cmd = ["netsh", "advfirewall", "set",
               "allprofiles", "state", state]
        ok, out = self._run(cmd)
        return ok, f"Firewall {state.upper()}!" if ok else out
