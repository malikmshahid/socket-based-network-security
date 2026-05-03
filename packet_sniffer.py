"""
=============================================================================
packet_sniffer.py  –  Live Network Packet Sniffer
=============================================================================
AI-Powered Vulnerability Assessment System  v7.0
Real-time capture of network packets using raw sockets.
Shows: source IP, dest IP, protocol, port, size, flags, threat tag.
No external libraries needed (pure Python socket).
=============================================================================
"""

import socket
import struct
import threading
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Protocol numbers ────────────────────────────────────────────────────────
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 2: "IGMP", 47: "GRE", 50: "ESP"}

# ── Ports that deserve a threat tag ────────────────────────────────────────
SUSPICIOUS_PORTS = {
    21:   ("FTP",        "WARN"),
    22:   ("SSH",        "INFO"),
    23:   ("TELNET",     "CRIT"),
    25:   ("SMTP",       "WARN"),
    53:   ("DNS",        "INFO"),
    80:   ("HTTP",       "INFO"),
    135:  ("RPC",        "WARN"),
    139:  ("NETBIOS",    "WARN"),
    443:  ("HTTPS",      "OK"),
    445:  ("SMB",        "CRIT"),
    1433: ("MSSQL",      "WARN"),
    3306: ("MYSQL",      "CRIT"),
    3389: ("RDP",        "CRIT"),
    4444: ("METERPRETER","CRIT"),
    5900: ("VNC",        "CRIT"),
    6666: ("BACKDOOR?",  "CRIT"),
    8080: ("HTTP-ALT",   "INFO"),
    9999: ("BACKDOOR?",  "CRIT"),
}


def _parse_ip_header(raw: bytes) -> dict | None:
    """Parse a raw IPv4 header."""
    try:
        if len(raw) < 20:
            return None
        ihl    = (raw[0] & 0x0F) * 4
        proto  = raw[9]
        src_ip = socket.inet_ntoa(raw[12:16])
        dst_ip = socket.inet_ntoa(raw[16:20])
        total  = struct.unpack("!H", raw[2:4])[0]
        payload = raw[ihl:]

        src_port = dst_port = flags_str = ""
        if proto == 6 and len(payload) >= 20:           # TCP
            src_port, dst_port = struct.unpack("!HH", payload[:4])
            tcp_flags = payload[13]
            fl = []
            if tcp_flags & 0x02: fl.append("SYN")
            if tcp_flags & 0x10: fl.append("ACK")
            if tcp_flags & 0x04: fl.append("RST")
            if tcp_flags & 0x01: fl.append("FIN")
            if tcp_flags & 0x08: fl.append("PSH")
            flags_str = "|".join(fl) if fl else "--"
        elif proto == 17 and len(payload) >= 8:          # UDP
            src_port, dst_port = struct.unpack("!HH", payload[:4])
            flags_str = "UDP"

        # Threat tag
        tag = "INFO"; service = ""
        for port in (src_port, dst_port):
            if port in SUSPICIOUS_PORTS:
                service, tag = SUSPICIOUS_PORTS[port]
                break

        return {
            "time":      datetime.now().strftime("%H:%M:%S"),
            "src_ip":    src_ip,
            "dst_ip":    dst_ip,
            "proto":     PROTO_NAMES.get(proto, str(proto)),
            "src_port":  str(src_port) if src_port else "--",
            "dst_port":  str(dst_port) if dst_port else "--",
            "size":      total,
            "flags":     flags_str,
            "service":   service,
            "tag":       tag,
        }
    except Exception:
        return None


class PacketSniffer:
    """
    Captures live packets on all interfaces using a raw socket.
    Calls packet_callback(pkt_dict) for each decoded packet.
    Requires Administrator / root privileges on most OSes.
    """

    def __init__(self, packet_callback=None, max_packets=500):
        self.callback    = packet_callback
        self.max_packets = max_packets
        self.running     = False
        self._thread     = None
        self.packets     = []           # rolling buffer
        self.stats       = {
            "total": 0, "tcp": 0, "udp": 0, "icmp": 0,
            "crit": 0, "warn": 0,
        }
        self._lock       = threading.Lock()

    # ── Public API ────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Open raw socket and start capture thread. Returns True if OK."""
        try:
            self._sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_RAW,
                socket.IPPROTO_IP
            )
            host = socket.gethostbyname(socket.gethostname())
            self._sock.bind((host, 0))
            import os
            if os.name == "nt":
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            self.running = True
            self._thread = threading.Thread(target=self._loop, daemon=True)
            self._thread.start()
            return True
        except PermissionError:
            logger.warning("PacketSniffer: needs Administrator privileges")
            return False
        except Exception as e:
            logger.error(f"PacketSniffer start error: {e}")
            return False

    def stop(self):
        self.running = False
        try:
            import os
            if os.name == "nt":
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self._sock.close()
        except Exception:
            pass

    def get_packets(self, n=100) -> list:
        with self._lock:
            return list(self.packets[-n:])

    def clear(self):
        with self._lock:
            self.packets.clear()
        self.stats = {k: 0 for k in self.stats}

    # ── Internal ──────────────────────────────────────────────────────────

    def _loop(self):
        while self.running:
            try:
                raw, _ = self._sock.recvfrom(65535)
                pkt = _parse_ip_header(raw)
                if pkt:
                    self._record(pkt)
            except OSError:
                break
            except Exception as e:
                logger.debug(f"Sniffer loop: {e}")

    def _record(self, pkt: dict):
        with self._lock:
            self.packets.append(pkt)
            if len(self.packets) > self.max_packets:
                self.packets.pop(0)

        self.stats["total"] += 1
        p = pkt["proto"]
        if p == "TCP":  self.stats["tcp"]  += 1
        elif p == "UDP": self.stats["udp"]  += 1
        elif p == "ICMP":self.stats["icmp"] += 1
        if pkt["tag"] == "CRIT": self.stats["crit"] += 1
        elif pkt["tag"] == "WARN":self.stats["warn"] += 1

        if self.callback:
            try:
                self.callback(pkt)
            except Exception:
                pass
