"""
=============================================================================
ai_assistant.py - Built-in AI Security Assistant
=============================================================================
AI-Powered Vulnerability Assessment System v6.0
Security questions ke jawab deta hai — offline knowledge base
=============================================================================
"""

import re
from datetime import datetime

# ── Knowledge Base ─────────────────────────────────────────────────────────

KB = {
    # Ports
    "port 21":   ("FTP port 21 is DANGEROUS — transfers data in plaintext. Attackers can sniff credentials. "
                  "FIX: Block with firewall or use SFTP (port 22) instead."),
    "port 22":   ("SSH port 22 is generally safe but often targeted by brute-force attacks. "
                  "FIX: Change to non-standard port, use key-based auth, disable root login."),
    "port 23":   ("Telnet port 23 is CRITICAL RISK — completely unencrypted. "
                  "All data including passwords sent as plaintext. NEVER use Telnet. Use SSH instead."),
    "port 80":   ("HTTP port 80 is unencrypted web traffic. Vulnerable to MITM attacks. "
                  "FIX: Use HTTPS (port 443) with SSL/TLS certificate."),
    "port 443":  ("HTTPS port 443 is encrypted web traffic — generally safe. "
                  "Ensure valid SSL certificate and TLS 1.2+ is configured."),
    "port 445":  ("SMB port 445 is CRITICAL — used by WannaCry ransomware (CVE-2017-0144). "
                  "FIX: Block immediately: netsh advfirewall firewall add rule name=BlockSMB protocol=TCP dir=in localport=445 action=block"),
    "port 3389": ("RDP port 3389 is CRITICAL — BlueKeep (CVE-2019-0708) can give full control without password. "
                  "FIX: Disable or block: netsh advfirewall firewall add rule name=BlockRDP protocol=TCP dir=in localport=3389 action=block"),
    "port 8080": ("HTTP alternate port 8080 — often used by web servers and proxies. "
                  "Ensure it is not exposing admin panels or development servers publicly."),

    # Attacks
    "brute force":   ("Brute force attack = automated tool tries thousands of passwords per second. "
                      "FIX: Set lockout policy (net accounts /lockoutthreshold:5) and use 12+ char passwords."),
    "ransomware":    ("Ransomware encrypts all your files and demands payment. WannaCry used SMB port 445. "
                      "FIX: Block port 445, keep Windows updated, regular backups, Defender ON."),
    "mitm":          ("Man-in-the-Middle = attacker intercepts all traffic between you and server. "
                      "FIX: Avoid public WiFi, use HTTPS only, VPN recommended."),
    "phishing":      ("Phishing = fake emails/websites steal your credentials. "
                      "FIX: Never click unknown links, verify sender, use 2FA on all accounts."),
    "sql injection": ("SQL Injection = attacker injects malicious SQL code into input fields. "
                      "FIX: Use parameterized queries, input validation, WAF protection."),
    "xss":           ("Cross-Site Scripting = malicious scripts injected into web pages. "
                      "FIX: Input sanitization, Content Security Policy headers."),
    "ddos":          ("DDoS = Distributed Denial of Service — flood server with traffic to crash it. "
                      "FIX: Rate limiting, CDN with DDoS protection, firewall rules."),
    "zero day":      ("Zero-day = vulnerability discovered before vendor knows about it — no patch exists yet. "
                      "HIGH RISK. Keep all software updated. Monitor CVE databases."),

    # CVEs
    "cve-2017-0144": ("EternalBlue — SMB vulnerability used by WannaCry ransomware. "
                       "Infected 200,000+ systems in 150 countries. $4 billion damage. "
                       "FIX: Block port 445, install MS17-010 patch."),
    "cve-2019-0708": ("BlueKeep — RDP vulnerability giving full control without password. "
                       "1 million+ systems were exposed. Microsoft issued emergency patch even for XP. "
                       "FIX: Disable RDP, install patch KB4499175."),
    "cve-2021-44228":("Log4Shell — Apache Log4j CVSS 10.0. One malicious string = full server control. "
                       "Billions of servers affected including iCloud, Minecraft, AWS. "
                       "FIX: Update Log4j to 2.17.1+"),
    "log4shell":     ("Log4Shell (CVE-2021-44228) — worst vulnerability of 2021. CVSS: 10.0/10. "
                       "Sending a crafted string caused remote code execution on billions of servers. "
                       "FIX: Update Apache Log4j immediately."),
    "wannacry":      ("WannaCry — 2017 ransomware that infected 200,000+ systems worldwide in 150 countries. "
                       "Used NSA's EternalBlue exploit (CVE-2017-0144) on SMB port 445. "
                       "$4 billion total damage. NHS hospitals shut down. "
                       "FIX: Block port 445, patch Windows with MS17-010."),
    "bluekeep":      ("BlueKeep (CVE-2019-0708) — RDP vulnerability requiring zero authentication. "
                       "Attacker gets full system control remotely. 1M+ systems exposed. "
                       "FIX: Disable RDP service, install emergency patch."),

    # General security
    "firewall":      ("Firewall monitors and controls network traffic based on rules. "
                       "Windows Firewall should ALWAYS be ON. "
                       "CHECK: netsh advfirewall show allprofiles  "
                       "ENABLE: netsh advfirewall set allprofiles state on"),
    "antivirus":     ("Antivirus/Windows Defender scans for malware in real-time. "
                       "Should always be active and updated. "
                       "CHECK: sc query WinDefend  |  UPDATE: MpCmdRun.exe -SignatureUpdate"),
    "password":      ("Strong passwords: 12+ chars, uppercase, lowercase, numbers, special chars. "
                       "Never reuse passwords. Use password manager. Enable 2FA where possible. "
                       "Set policy: net accounts /minpwlen:12 /lockoutthreshold:5"),
    "vpn":           ("VPN encrypts all your internet traffic — essential on public WiFi. "
                       "Hides your IP address. Prevents ISP tracking and MITM attacks on unsecured networks."),
    "2fa":           ("Two-Factor Authentication adds a second verification step beyond password. "
                       "Even if password is stolen, attacker cannot login without the second factor. "
                       "ALWAYS enable 2FA on email, banking, social media accounts."),
    "encryption":    ("Encryption converts data to unreadable format without the key. "
                       "HTTPS uses TLS encryption. Use BitLocker for disk encryption. "
                       "Encrypt sensitive files before email."),
    "patch":         ("Security patches fix known vulnerabilities. "
                       "Unpatched systems are primary targets. "
                       "WannaCry only infected UNPATCHED Windows systems. "
                       "Run: wuauclt /updatenow  to force Windows Update."),
    "backup":        ("Regular backups are your last defense against ransomware. "
                       "3-2-1 rule: 3 copies, 2 different media, 1 offsite. "
                       "Test backups regularly. Offline/air-gapped backups are safest."),
    "risk score":    ("Risk score is calculated from 5 factors: Open Ports (25%), Firewall (25%), "
                       "OS Updates (20%), Antivirus (20%), Critical Ports (10%). "
                       "Score 0-30: LOW | 31-50: MEDIUM | 51-75: HIGH | 76-100: CRITICAL"),

    # Windows specific
    "netstat":       ("netstat -ano shows all active network connections and listening ports. "
                       "Each line: Protocol, Local Address:Port, Foreign Address:Port, State, PID. "
                       "PID can be matched to process in Task Manager."),
    "windows defender":("Windows Defender is Microsoft's built-in antivirus — FREE and effective. "
                         "Enabled by default. Check: sc query WinDefend  "
                         "Force scan: MpCmdRun.exe -Scan -ScanType 2"),
}

GREETINGS = ["hello","hi","salam","assalam","hey","helo"]
HELP_WORDS = ["help","what can you do","features","commands"]


class SecurityAssistant:
    """
    Offline AI security assistant.
    Answers questions about cybersecurity using built-in knowledge base.
    """

    def __init__(self):
        self.conversation = []
        self.query_count  = 0

    def ask(self, question: str) -> str:
        """Process question and return answer."""
        self.query_count += 1
        q = question.strip().lower()
        self.conversation.append({"role":"user","text":question,"time":datetime.now().strftime("%H:%M")})

        answer = self._find_answer(q)
        self.conversation.append({"role":"bot","text":answer,"time":datetime.now().strftime("%H:%M")})
        return answer

    def _find_answer(self, q: str) -> str:
        # Greeting
        if any(g in q for g in GREETINGS):
            return ("Hello! I am your AI Security Assistant. 🔐\n\n"
                    "Ask me about:\n"
                    "  • Ports (e.g. 'what is port 445?')\n"
                    "  • Attacks (e.g. 'explain ransomware')\n"
                    "  • CVEs (e.g. 'tell me about WannaCry')\n"
                    "  • Security tips (e.g. 'how to make strong password?')\n"
                    "  • Commands (e.g. 'how to check firewall?')")

        # Help
        if any(h in q for h in HELP_WORDS):
            topics = list(KB.keys())
            return (f"I can answer questions about {len(topics)} security topics!\n\n"
                    f"Topics include: {', '.join(topics[:15])}...\n\n"
                    "Just ask naturally — e.g. 'what is ransomware?' or 'explain port 3389'")

        # Risk score questions
        if "risk" in q and ("score" in q or "calculate" in q or "how" in q):
            return KB["risk score"]

        # Direct KB lookup
        for key, answer in KB.items():
            if key in q:
                return f"📋 {key.upper()}\n\n{answer}"

        # Port number extraction
        port_match = re.search(r'port\s*(\d+)', q)
        if port_match:
            port = port_match.group(1)
            key = f"port {port}"
            if key in KB:
                return f"📋 {key.upper()}\n\n{KB[key]}"
            else:
                return (f"Port {port} is not in my database.\n\n"
                        f"General advice: If port {port} is open and not needed, "
                        f"block it with firewall:\n"
                        f"netsh advfirewall firewall add rule name=BlockPort{port} "
                        f"protocol=TCP dir=in localport={port} action=block")

        # CVE extraction
        cve_match = re.search(r'cve[-\s](\d{4})[-\s](\d+)', q)
        if cve_match:
            cve_id = f"cve-{cve_match.group(1)}-{cve_match.group(2)}"
            if cve_id in KB:
                return f"📋 {cve_id.upper()}\n\n{KB[cve_id]}"

        # Fuzzy matching
        q_words = set(q.split())
        best_key = None; best_score = 0
        for key in KB:
            key_words = set(key.split())
            overlap = len(q_words & key_words)
            if overlap > best_score:
                best_score = overlap; best_key = key
        if best_score >= 1 and best_key:
            return f"📋 Related: {best_key.upper()}\n\n{KB[best_key]}"

        # Default
        suggestions = []
        for key in list(KB.keys())[:8]:
            suggestions.append(f"  • '{key}'")
        return (f"I don't have specific info about that.\n\n"
                f"Try asking about:\n" + "\n".join(suggestions) +
                f"\n\nOr be more specific — e.g. 'explain port 445' or 'what is ransomware?'")
