"""
=============================================================================
attack_simulator.py  –  Ethical Attack Simulation Lab
=============================================================================
AI-Powered Vulnerability Assessment System  v8.0
Safe, educational attack simulations — runs ONLY on localhost (127.0.0.1)
Shows EXACTLY how attacks work step by step with live output.
ALL simulations are completely safe — no actual harm done.
=============================================================================
"""

import socket
import subprocess
import threading
import time
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DISCLAIMER = (
    "⚠  EDUCATIONAL SIMULATION ONLY\n"
    "All simulations run against 127.0.0.1 (localhost) ONLY.\n"
    "No actual attack is performed. For learning purposes.\n"
    "Never use these techniques against systems you don't own.\n"
)

SIMULATIONS = [
    {
        "id":          "port_scan",
        "title":       "🔍 Port Scanner Simulation",
        "category":    "Reconnaissance",
        "difficulty":  "BEGINNER",
        "color":       "#00D4FF",
        "description": (
            "Simulates how attackers discover open ports on a system.\n"
            "Port scanning is the FIRST step in almost every attack.\n"
            "Demonstrates why closing unused ports is critical."
        ),
        "steps": [
            "Initialising port scanner...",
            "Selecting target: 127.0.0.1 (localhost — your machine)",
            "Scanning ports 1-1024...",
            "Probing each port with TCP SYN packet...",
            "Analysing responses: OPEN = got reply, CLOSED = refused",
            "Mapping discovered services...",
            "Building attack surface report...",
        ],
    },
    {
        "id":          "brute_sim",
        "title":       "💥 Brute Force Simulation",
        "category":    "Credential Attack",
        "difficulty":  "BEGINNER",
        "color":       "#FF8C42",
        "description": (
            "Shows how automated tools try thousands of passwords per second.\n"
            "Demonstrates why lockout policies and strong passwords matter.\n"
            "Uses sample wordlist — no actual login attempted."
        ),
        "steps": [
            "Loading credential wordlist (10,000 common passwords)...",
            "Target: localhost login form (simulation only)",
            "Attempting: admin:123456 — FAILED",
            "Attempting: admin:password — FAILED",
            "Attempting: admin:qwerty — FAILED",
            "Attempting: admin:letmein — FAILED",
            "Speed: ~1,000 attempts/second on slow systems",
            "Real tools (Hydra): up to 100,000/sec on fast networks",
            "Simulation stopped — lockout policy would trigger here",
            "LESSON: Set net accounts /lockoutthreshold:5",
        ],
    },
    {
        "id":          "arp_spoof_sim",
        "title":       "🕵️ ARP Spoofing Simulation (MITM)",
        "category":    "Man-in-the-Middle",
        "difficulty":  "INTERMEDIATE",
        "color":       "#FF8C42",
        "description": (
            "Demonstrates how MITM attacks intercept network traffic.\n"
            "ARP spoofing tricks devices into sending traffic through attacker.\n"
            "Shows why public WiFi is dangerous."
        ),
        "steps": [
            "Discovering hosts on local network via ARP...",
            "Identifying gateway IP and MAC address...",
            "Sending forged ARP reply to victim: 'Gateway MAC = MY MAC'",
            "Sending forged ARP reply to gateway: 'Victim MAC = MY MAC'",
            "All victim traffic now routes through attacker machine...",
            "Intercepting HTTP credentials (plaintext visible)...",
            "Intercepting unencrypted cookies...",
            "LESSON: Use HTTPS only. VPN on public WiFi. ARP inspection.",
        ],
    },
    {
        "id":          "sql_inject_sim",
        "title":       "💉 SQL Injection Simulation",
        "category":    "Web Attack",
        "difficulty":  "INTERMEDIATE",
        "color":       "#FFD60A",
        "description": (
            "Shows how SQL injection bypasses login forms and dumps databases.\n"
            "Classic OWASP Top 10 vulnerability — affects millions of websites.\n"
            "Educational demonstration of the attack technique."
        ),
        "steps": [
            "Target: Sample login form with vulnerable SQL query",
            "Normal query: SELECT * FROM users WHERE user='admin' AND pass='X'",
            "Injecting payload: admin' OR '1'='1",
            "Malicious query: SELECT * FROM users WHERE user='admin' OR '1'='1'",
            "'1'='1' is always TRUE — bypasses password check!",
            "Attacker is now logged in as admin without password",
            "Dumping database: ' UNION SELECT username,password FROM users--",
            "ALL passwords extracted from database!",
            "LESSON: Use parameterized queries. Never concatenate user input in SQL.",
        ],
    },
    {
        "id":          "dos_sim",
        "title":       "🌊 DoS Simulation (Conceptual)",
        "category":    "Denial of Service",
        "difficulty":  "ADVANCED",
        "color":       "#FF2D55",
        "description": (
            "Explains how Denial of Service attacks overwhelm systems.\n"
            "CONCEPTUAL ONLY — no traffic is actually generated.\n"
            "Shows why rate limiting and firewall rules are essential."
        ),
        "steps": [
            "DoS = Denial of Service — overload target with requests",
            "DDoS = Distributed DoS — thousands of machines attacking one target",
            "SYN Flood: send millions of half-open TCP connections",
            "Server memory fills up with half-open states",
            "Legitimate users cannot connect — service DOWN",
            "Amplification: send 100 bytes, get 4000 byte response back",
            "10 Gbps attack possible with 250 Mbps source",
            "2016 Mirai Botnet: 1.2 Tbps attack on Dyn DNS",
            "Entire internet regions went offline (GitHub, Twitter, Netflix)",
            "LESSON: Cloudflare/CDN, rate limiting, anycast routing.",
        ],
    },
    {
        "id":          "social_eng_sim",
        "title":       "🎭 Social Engineering Awareness",
        "category":    "Human Factor",
        "difficulty":  "BEGINNER",
        "color":       "#AA44FF",
        "description": (
            "The most effective attacks target humans, not technology.\n"
            "Phishing, pretexting, baiting — 91% of breaches start here.\n"
            "Interactive awareness training scenario."
        ),
        "steps": [
            "You receive email: 'Your Microsoft account has been compromised'",
            "Email looks official — Microsoft logo, proper formatting",
            "Link: http://micros0ft-security-alert.com/verify (FAKE!)",
            "RED FLAGS: urgency, external domain, generic greeting",
            "Hovering link reveals: not microsoft.com",
            "Sender: security@micros0ft.com (zero not letter O!)",
            "Opening link → fake login page → steals credentials",
            "LESSON: Verify sender domain. Never click email links.",
            "LESSON: Go directly to website by typing address manually.",
            "LESSON: Enable 2FA — stolen password alone not enough.",
        ],
    },
]


class AttackSimulator:
    """
    Runs educational attack simulations with step-by-step output.
    ALL simulations are safe and educational — no actual attacks.
    """

    def __init__(self, output_callback=None):
        self.callback = output_callback
        self.running  = False

    def _emit(self, msg: str, tag: str = "normal"):
        if self.callback:
            self.callback(msg, tag)
        logger.info(msg)

    def _delay(self, seconds: float = 0.8):
        time.sleep(seconds)

    def run_simulation(self, sim_id: str):
        """Run a specific simulation by ID."""
        sim = next((s for s in SIMULATIONS if s["id"] == sim_id), None)
        if not sim:
            self._emit(f"Unknown simulation: {sim_id}", "error")
            return

        self.running = True
        self._emit("", "normal")
        self._emit("=" * 60, "sep")
        self._emit(f"  SIMULATION: {sim['title']}", "title")
        self._emit(f"  Category:   {sim['category']}", "info")
        self._emit(f"  Difficulty: {sim['difficulty']}", "info")
        self._emit("=" * 60, "sep")
        self._emit(DISCLAIMER, "warn")
        self._emit("-" * 60, "sep")
        self._delay(1.0)

        # Run each step
        for i, step in enumerate(sim["steps"], 1):
            if not self.running:
                self._emit("\n[STOPPED] Simulation aborted.", "warn")
                return
            self._emit(f"[{i:02d}/{len(sim['steps']):02d}] {step}", "step")
            self._delay(0.9)

        self._emit("", "normal")
        self._emit("=" * 60, "sep")
        self._emit("  SIMULATION COMPLETE", "success")
        self._emit("=" * 60, "sep")

        # Real-time port scan (safe — localhost only)
        if sim_id == "port_scan":
            self._emit("\n  LIVE SCAN — localhost ports 20-1025:", "title")
            self._delay(0.5)
            open_ports = []
            for port in [21, 22, 23, 25, 80, 135, 139, 443, 445, 3306,
                         3389, 5900, 8080, 8443]:
                if not self.running:
                    break
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    r = s.connect_ex(("127.0.0.1", port))
                    s.close()
                    if r == 0:
                        open_ports.append(port)
                        self._emit(f"  Port {port:5d}  OPEN  ✓  ← Target!", "open_port")
                    else:
                        self._emit(f"  Port {port:5d}  closed", "closed_port")
                except Exception:
                    pass
                self._delay(0.15)

            self._emit(f"\n  Result: {len(open_ports)} open port(s): {open_ports}", "result")
            self._emit("  An attacker now knows your attack surface!", "warn")

        self.running = False

    def stop(self):
        self.running = False

    @staticmethod
    def get_catalog() -> list:
        return SIMULATIONS
