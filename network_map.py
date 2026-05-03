import socket
import subprocess
import threading
import platform
import re
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class NetworkMapper:
  
    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback
        self.devices = []

    def _log(self, msg):
        if self.progress_callback:
            self.progress_callback(msg)
        logger.info(msg)

    def get_local_subnet(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            parts = ip.split(".")
            return ".".join(parts[:3])
        except Exception:
            return "192.168.1"

    def get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return 

    def ping_host(self, ip: str) -> bool:
        try:
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "500", ip]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", ip]
            result = subprocess.run(cmd, capture_output=True, timeout=2,
                                    creationflags=subprocess.CREATE_NO_WINDOW
                                    if os.name == "nt" else 0)
            return result.returncode == 0
        except Exception:
            return False

    def get_mac_address(self, ip: str) -> str:
        try:
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True, text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )
            # Extract MAC from ARP output
            mac_pattern = r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}"
            match = re.search(mac_pattern, result.stdout)
            if match:
                return match.group().upper()
        except Exception:
            pass
        return "Unknown"

    def get_hostname(self, ip: str) -> str:
        """Reverse DNS lookup for hostname."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return "Unknown"

    def get_device_type(self, mac: str) -> str:
        """Guess device type from MAC OUI prefix."""
        if mac == "Unknown":
            return "Unknown Device"
        oui = mac.replace("-", ":").upper()[:8]
        # Common OUI prefixes
        vendors = {
            "00:50:56": "VMware VM",
            "00:0C:29": "VMware VM",
            "08:00:27": "VirtualBox VM",
            "DC:A6:32": "Raspberry Pi",
            "B8:27:EB": "Raspberry Pi",
            "FC:AA:14": "Apple Device",
            "A4:C3:F0": "Apple iPhone",
            "00:1A:2B": "Cisco Router",
            "E4:5F:01": "TP-Link Router",
            "C8:3A:35": "Tenda Router",
            "00:E0:4C": "Realtek NIC",
        }
        for prefix, name in vendors.items():
            if oui.startswith(prefix):
                return name
        return "Network Device"

    def scan_network(self, subnet: str = None) -> list:
        """
        Scan entire /24 subnet for live hosts.
        Returns list of device dicts.
        """
        if not subnet:
            subnet = self.get_local_subnet()

        local_ip = self.get_local_ip()
        self._log(f"[NET-MAP] Starting network scan on {subnet}.0/24")
        self._log(f"[NET-MAP] Your IP: {local_ip}")
        self._log(f"[NET-MAP] Scanning 254 hosts... (this may take 30-60s)")

        self.devices = []
        lock = threading.Lock()
        threads = []
        found_count = [0]

        def scan_ip(ip):
            if self.ping_host(ip):
                mac      = self.get_mac_address(ip)
                hostname = self.get_hostname(ip)
                dev_type = self.get_device_type(mac)
                is_local = (ip == local_ip)

                device = {
                    "ip":       ip,
                    "mac":      mac,
                    "hostname": hostname[:30] if hostname != "Unknown" else "Unknown",
                    "type":     dev_type,
                    "is_local": is_local,
                    "status":   "ONLINE",
                    "label":    "THIS DEVICE" if is_local else dev_type,
                }
                with lock:
                    self.devices.append(device)
                    found_count[0] += 1
                self._log(
                    f"[NET-MAP] ✓ FOUND: {ip:<16} | {mac:<20} | {hostname[:25]}"
                )

        # Scan in batches of 20 threads
        all_ips = [f"{subnet}.{i}" for i in range(1, 255)]
        batch_size = 20

        for i in range(0, len(all_ips), batch_size):
            batch = all_ips[i:i+batch_size]
            batch_threads = []
            for ip in batch:
                t = threading.Thread(target=scan_ip, args=(ip,), daemon=True)
                batch_threads.append(t)
                t.start()
            for t in batch_threads:
                t.join(timeout=3)

        # Sort by IP
        self.devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])

        self._log(f"[NET-MAP] Scan complete. {found_count[0]} device(s) found.")
        return self.devices
