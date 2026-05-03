"""
=============================================================================
scanner.py - Vulnerability Scanner Module
=============================================================================
AI-Powered Intelligent Vulnerability Assessment & Threat Prediction System
Final Year Project - Computer Science

Description:
    This module handles all network scanning and system information gathering.
    It supports both nmap-based scanning (if installed) and a fallback
    socket-based scanner for environments without nmap.

Author: FYP Student
Version: 1.0
=============================================================================
"""

import socket
import subprocess
import platform
import os
import logging
from datetime import datetime

# Configure logging for debug/info output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Try importing optional nmap library
try:
    import nmap
    NMAP_AVAILABLE = True
    logger.info("python-nmap library found. nmap scanning enabled.")
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("python-nmap not found. Using socket-based fallback scanner.")


class VulnerabilityScanner:
    """
    Main vulnerability scanner class.
    
    Performs port scanning, system information gathering, and
    security checks (firewall, antivirus, OS update status).
    
    Attributes:
        target_ip (str): The IP address to scan.
        scan_results (dict): Dictionary storing all scan results.
        common_ports (list): List of ports to check during scan.
        critical_ports (list): High-risk ports that require special attention.
    """

    # Standard ports to scan
    COMMON_PORTS = [
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        135,   # RPC
        139,   # NetBIOS
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP (Remote Desktop)
        5900,  # VNC
        8080,  # HTTP Alternate
        8443,  # HTTPS Alternate
    ]

    # Critical ports — their exposure significantly raises risk
    CRITICAL_PORTS = [21, 22, 23, 135, 139, 445, 3389]

    # Service names for display
    PORT_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        135: "Windows RPC",
        139: "NetBIOS",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB/Windows File Sharing",
        3306: "MySQL Database",
        3389: "Remote Desktop (RDP)",
        5900: "VNC Remote Desktop",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
    }

    def __init__(self, target_ip="127.0.0.1"):
        """
        Initialize the scanner with a target IP address.

        Args:
            target_ip (str): IP address to scan. Defaults to localhost.
        """
        self.target_ip = target_ip
        self.scan_results = {}
        self.scan_timestamp = None
        logger.info(f"VulnerabilityScanner initialized for target: {target_ip}")

    def run_full_scan(self, progress_callback=None):
        """
        Execute a complete vulnerability scan.

        This is the main entry point for scanning. It runs all sub-modules
        and compiles results into the scan_results dictionary.

        Args:
            progress_callback (callable): Optional function(message: str) to
                                          send real-time updates to the GUI.

        Returns:
            dict: Complete scan results.
        """
        self.scan_timestamp = datetime.now()
        self.scan_results = {
            "timestamp": self.scan_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "target_ip": self.target_ip,
            "system_info": {},
            "open_ports": [],
            "critical_ports_open": [],
            "firewall_status": "Unknown",
            "antivirus_status": "Unknown",
            "os_update_status": "Unknown",
            "errors": [],
        }

        def log(msg):
            logger.info(msg)
            if progress_callback:
                progress_callback(msg)

        # ── Step 1: System Information ────────────────────────────────────
        log("[*] Gathering system information...")
        self.scan_results["system_info"] = self._get_system_info()
        log(f"    Hostname : {self.scan_results['system_info'].get('hostname', 'N/A')}")
        log(f"    OS       : {self.scan_results['system_info'].get('os', 'N/A')}")
        log(f"    Local IP : {self.scan_results['system_info'].get('local_ip', 'N/A')}")

        # ── Step 2: Port Scanning ─────────────────────────────────────────
        log(f"\n[*] Starting port scan on {self.target_ip}...")
        if NMAP_AVAILABLE:
            log("    Using nmap scanner...")
            self._scan_with_nmap(log)
        else:
            log("    nmap not found — using socket-based scanner...")
            self._scan_with_sockets(log)

        critical_open = [p for p in self.scan_results["open_ports"] if p in self.CRITICAL_PORTS]
        self.scan_results["critical_ports_open"] = critical_open
        log(f"    Open ports found   : {len(self.scan_results['open_ports'])}")
        log(f"    Critical ports open: {len(critical_open)}")

        # ── Step 3: Firewall Status ───────────────────────────────────────
        log("\n[*] Checking Windows Firewall status...")
        self.scan_results["firewall_status"] = self._check_firewall()
        log(f"    Firewall: {self.scan_results['firewall_status']}")

        # ── Step 4: Antivirus Status ──────────────────────────────────────
        log("\n[*] Checking Antivirus / Windows Defender status...")
        self.scan_results["antivirus_status"] = self._check_antivirus()
        log(f"    Antivirus: {self.scan_results['antivirus_status']}")

        # ── Step 5: OS Update Status ──────────────────────────────────────
        log("\n[*] Checking OS update status...")
        self.scan_results["os_update_status"] = self._check_os_updates()
        log(f"    OS Updates: {self.scan_results['os_update_status']}")

        log("\n[✓] Scan complete.")
        return self.scan_results

    # ──────────────────────────────────────────────────────────────────────
    # PRIVATE METHODS
    # ──────────────────────────────────────────────────────────────────────

    def _get_system_info(self):
        """
        Collect basic system information using the platform module.

        Returns:
            dict: System details (hostname, OS, IP, architecture, etc.)
        """
        info = {}
        try:
            info["hostname"] = socket.gethostname()
        except Exception:
            info["hostname"] = "Unknown"

        try:
            info["local_ip"] = socket.gethostbyname(info.get("hostname", "localhost"))
        except Exception:
            info["local_ip"] = "127.0.0.1"

        info["os"] = platform.system()
        info["os_version"] = platform.version()
        info["os_release"] = platform.release()
        info["architecture"] = platform.architecture()[0]
        info["processor"] = platform.processor() or "Unknown"
        info["python_version"] = platform.python_version()

        return info

    def _scan_with_sockets(self, log_func=None):
        """
        Socket-based port scanner fallback (no nmap required).
        
        Uses socket.connect_ex() which returns 0 if the port is open,
        making it safe and non-destructive.

        Args:
            log_func (callable): Logging callback for GUI updates.
        """
        open_ports = []
        total = len(self.COMMON_PORTS)

        for idx, port in enumerate(self.COMMON_PORTS):
            if log_func:
                log_func(f"    Scanning port {port} ({self.PORT_SERVICES.get(port, 'Unknown')})... [{idx+1}/{total}]")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)  # 1 second timeout per port
                result = sock.connect_ex((self.target_ip, port))
                sock.close()

                if result == 0:
                    service = self.PORT_SERVICES.get(port, "Unknown Service")
                    open_ports.append(port)
                    if log_func:
                        log_func(f"      → Port {port} OPEN  [{service}]")
            except socket.error as e:
                self.scan_results["errors"].append(f"Socket error on port {port}: {str(e)}")

        self.scan_results["open_ports"] = open_ports

    def _scan_with_nmap(self, log_func=None):
        """
        nmap-based port scanner (requires python-nmap and nmap installed).

        Args:
            log_func (callable): Logging callback for GUI updates.
        """
        open_ports = []
        try:
            nm = nmap.PortScanner()
            port_range = ",".join(str(p) for p in self.COMMON_PORTS)
            nm.scan(hosts=self.target_ip, ports=port_range, arguments="-sV --open")

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    port_list = nm[host][proto].keys()
                    for port in port_list:
                        state = nm[host][proto][port]["state"]
                        service = nm[host][proto][port].get("name", "Unknown")
                        if state == "open":
                            open_ports.append(port)
                            if log_func:
                                log_func(f"      → Port {port} OPEN  [{service}]")
        except Exception as e:
            error_msg = f"nmap scan failed: {str(e)}. Falling back to socket scanner."
            self.scan_results["errors"].append(error_msg)
            if log_func:
                log_func(f"    [!] {error_msg}")
            self._scan_with_sockets(log_func)
            return

        self.scan_results["open_ports"] = open_ports

    def _check_firewall(self):
        """
        Check Windows Firewall status via netsh command.

        Returns:
            str: "ENABLED", "DISABLED", or "Unknown".
        """
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles", "state"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            output = result.stdout.lower()
            if "on" in output:
                return "ENABLED"
            elif "off" in output:
                return "DISABLED"
            return "Unknown"
        except Exception as e:
            self.scan_results["errors"].append(f"Firewall check error: {str(e)}")
            return "Unknown"

    def _check_antivirus(self):
        """
        Check Windows Defender / antivirus status via PowerShell.

        Returns:
            str: "ACTIVE", "INACTIVE", or "Unknown".
        """
        # Method 1: PowerShell Get-MpComputerStatus
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled"],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            output = result.stdout.strip().lower()
            if "true" in output:
                return "ACTIVE"
            elif "false" in output:
                return "INACTIVE"
        except Exception:
            pass

        # Method 2: sc query WinDefend (fallback)
        try:
            result = subprocess.run(
                ["sc", "query", "WinDefend"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            output = result.stdout.lower()
            if "running" in output:
                return "ACTIVE"
            elif "stopped" in output:
                return "INACTIVE"
        except Exception as e:
            self.scan_results["errors"].append(f"Antivirus check error: {str(e)}")

        return "Unknown"

    def _check_os_updates(self):
        """
        Check Windows Update status via PowerShell.

        Returns:
            str: "UP-TO-DATE", "UPDATES AVAILABLE", or "Unknown".
        """
        try:
            ps_script = (
                "Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue; "
                "$updates = Get-WindowsUpdate -ErrorAction SilentlyContinue; "
                "if ($updates) { Write-Output 'UPDATES_AVAILABLE' } "
                "else { Write-Output 'UP_TO_DATE' }"
            )
            result = subprocess.run(
                ["powershell", "-Command", ps_script],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            output = result.stdout.strip().upper()
            if "UPDATES_AVAILABLE" in output:
                return "UPDATES AVAILABLE"
            elif "UP_TO_DATE" in output:
                return "UP-TO-DATE"
        except Exception:
            pass

        # Fallback: check Windows Update service status
        try:
            result = subprocess.run(
                ["sc", "query", "wuauserv"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if "running" in result.stdout.lower():
                return "Update Service Running"
            return "Update Service Stopped"
        except Exception as e:
            self.scan_results["errors"].append(f"OS update check error: {str(e)}")
            return "Unknown"

    def get_port_service(self, port):
        """
        Return human-readable service name for a given port number.

        Args:
            port (int): Port number.

        Returns:
            str: Service name or 'Unknown Service'.
        """
        return self.PORT_SERVICES.get(port, "Unknown Service")


# ──────────────────────────────────────────────────────────────────────────
# Quick standalone test
# ──────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("=" * 60)
    print("  VulnerabilityScanner - Standalone Test")
    print("=" * 60)

    def console_log(msg):
        print(msg)

    scanner = VulnerabilityScanner("127.0.0.1")
    results = scanner.run_full_scan(progress_callback=console_log)

    print("\n--- RESULTS SUMMARY ---")
    print(f"Open Ports       : {results['open_ports']}")
    print(f"Critical Ports   : {results['critical_ports_open']}")
    print(f"Firewall         : {results['firewall_status']}")
    print(f"Antivirus        : {results['antivirus_status']}")
    print(f"OS Updates       : {results['os_update_status']}")
