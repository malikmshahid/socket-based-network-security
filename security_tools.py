"""
security_tools.py  -  FYP v10.0 Security Tools Bundle
Contains: Port Knocking, Ransomware Monitor, VPN Checker, Fake AP Detector,
          Keylogger Scanner, Phishing Analyzer, WiFi Passwords, System Analytics
"""
import os, subprocess, socket, threading, time, re, json, hashlib, logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def _run(cmd, timeout=20):
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=flags)
        # Use utf-8 with errors='replace' to handle Windows cp1252 issues
        out = r.stdout.decode("utf-8", errors="replace") if r.stdout else ""
        err = r.stderr.decode("utf-8", errors="replace") if r.stderr else ""
        return out + err
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except Exception as e:
        return str(e)

# ══════════════════════════════════════════════════════════════════════════
# 1. WiFi Saved Passwords
# ══════════════════════════════════════════════════════════════════════════

def get_wifi_passwords() -> list:
    """Get saved WiFi passwords using netsh (Windows only)."""
    profiles_out = _run(["netsh", "wlan", "show", "profiles"])
    profiles = []
    for line in profiles_out.splitlines():
        if "All User Profile" in line and ":" in line:
            name = line.split(":", 1)[1].strip()
            if name:
                profiles.append(name)

    results = []
    for profile in profiles:
        out = _run(["netsh", "wlan", "show", "profile",
                    f"name={profile}", "key=clear"])
        password = ""
        auth     = ""
        for line in out.splitlines():
            if "Key Content" in line and ":" in line:
                password = line.split(":", 1)[1].strip()
            if "Authentication" in line and ":" in line:
                auth = line.split(":", 1)[1].strip()
        results.append({
            "ssid":     profile,
            "password": password or "(No password / Open)",
            "auth":     auth or "Unknown",
            "has_pw":   bool(password),
        })
    return results


# ══════════════════════════════════════════════════════════════════════════
# 2. VPN Status Checker
# ══════════════════════════════════════════════════════════════════════════

VPN_INTERFACES = ["tun", "tap", "ppp", "vpn", "nordvpn", "expressvpn",
                  "proton", "wireguard", "openvpn", "cisco", "fortinet"]

def check_vpn_status() -> dict:
    """Detect active VPN connections."""
    vpn_found = []

    # Check network interfaces
    out = _run(["ipconfig", "/all"] if os.name == "nt" else ["ifconfig"])
    for line in out.lower().splitlines():
        for vpn_kw in VPN_INTERFACES:
            if vpn_kw in line:
                vpn_found.append(line.strip()[:60])

    # Check running processes
    procs = _run(["tasklist"] if os.name == "nt" else ["ps", "aux"])
    vpn_procs = []
    for vpn_kw in ["nordvpn", "expressvpn", "protonvpn", "openvpn",
                   "wireguard", "forticlient", "anyconnect", "tunnelbear"]:
        if vpn_kw in procs.lower():
            vpn_procs.append(vpn_kw)

    # Check public IP vs local
    public_ip = ""
    try:
        import urllib.request
        req = urllib.request.Request("https://api.ipify.org")
        req.add_header("User-Agent", "FYP/10.0")
        with urllib.request.urlopen(req, timeout=5) as r:
            public_ip = r.read().decode().strip()
    except Exception:
        pass

    active = bool(vpn_found or vpn_procs)
    return {
        "active":      active,
        "interfaces":  list(set(vpn_found))[:5],
        "processes":   vpn_procs,
        "public_ip":   public_ip,
        "status":      "🟢 VPN ACTIVE" if active else "🔴 NO VPN DETECTED",
        "risk":        "LOW" if active else "MEDIUM",
        "checked_at":  datetime.now().strftime("%H:%M:%S"),
    }


# ══════════════════════════════════════════════════════════════════════════
# 3. Phishing URL Analyzer
# ══════════════════════════════════════════════════════════════════════════

PHISHING_KEYWORDS = [
    "login", "signin", "account", "verify", "update", "secure", "banking",
    "paypal", "amazon", "apple", "google", "microsoft", "netflix", "ebay",
    "password", "confirm", "suspended", "unusual", "alert", "locked",
    "verify-account", "account-update", "security-alert", "click-here",
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
                   ".club", ".work", ".date", ".stream", ".download"]

LEGIT_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "paypal.com", "facebook.com", "twitter.com", "github.com",
    "stackoverflow.com", "wikipedia.org",
}

def analyze_url(url: str) -> dict:
    """Analyze URL for phishing indicators."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    score  = 0
    flags  = []
    try:
        from urllib.parse import urlparse
        parsed  = urlparse(url)
        domain  = parsed.netloc.lower().replace("www.", "")
        path    = parsed.path.lower()
        full    = (domain + path).lower()

        # HTTPS check
        if not url.startswith("https://"):
            score += 20
            flags.append("⚠ No HTTPS — data sent unencrypted")

        # IP address instead of domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            score += 35
            flags.append("🚨 IP address used instead of domain name")

        # Suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                score += 25
                flags.append(f"⚠ Suspicious free TLD: {tld}")
                break

        # Typosquatting / brand impersonation
        brands = ["paypa1", "arnazon", "g00gle", "micros0ft", "app1e",
                  "faceb00k", "netf1ix", "amaz0n", "paypol", "gooogle"]
        for brand in brands:
            if brand in domain:
                score += 40
                flags.append(f"🚨 Typosquatting detected: '{brand}'")

        # Legitimate brand in subdomain (impersonation)
        for legit in ["paypal", "apple", "google", "microsoft", "amazon", "netflix"]:
            if legit in domain and not any(domain.endswith(d) for d in LEGIT_DOMAINS):
                score += 30
                flags.append(f"🚨 Brand '{legit}' used in non-official domain")
                break

        # Phishing keywords in URL
        kw_found = [k for k in PHISHING_KEYWORDS if k in full]
        if len(kw_found) >= 3:
            score += 20
            flags.append(f"⚠ Multiple phishing keywords: {', '.join(kw_found[:4])}")
        elif len(kw_found) >= 1:
            score += 10
            flags.append(f"⚠ Phishing keyword found: {kw_found[0]}")

        # Excessive subdomains
        subdomain_count = domain.count(".")
        if subdomain_count >= 3:
            score += 15
            flags.append(f"⚠ Excessive subdomains ({subdomain_count})")

        # Very long URL
        if len(url) > 100:
            score += 10
            flags.append(f"⚠ Unusually long URL ({len(url)} chars)")

        # Known legit domain
        if any(domain == d or domain.endswith("." + d) for d in LEGIT_DOMAINS):
            score = max(0, score - 30)
            flags.append("✓ Recognized legitimate domain")

        score = min(score, 100)
        if score >= 70:   level = "CRITICAL"
        elif score >= 45: level = "HIGH"
        elif score >= 20: level = "MEDIUM"
        else:             level = "LOW"

        return {
            "url":     url,
            "domain":  domain,
            "score":   score,
            "level":   level,
            "flags":   flags,
            "verdict": "🚨 LIKELY PHISHING" if score >= 50 else
                       "⚠ SUSPICIOUS" if score >= 20 else "✓ PROBABLY SAFE",
            "https":   url.startswith("https://"),
        }
    except Exception as e:
        return {"url": url, "domain": "", "score": 0, "level": "UNKNOWN",
                "flags": [f"Error: {e}"], "verdict": "Could not analyze"}


# ══════════════════════════════════════════════════════════════════════════
# 4. Ransomware File Monitor
# ══════════════════════════════════════════════════════════════════════════

RANSOMWARE_EXTENSIONS = {
    ".encrypted", ".enc", ".locked", ".crypto", ".crypt", ".crypted",
    ".locky", ".cerber", ".wallet", ".wncry", ".wnry", ".wcry",
    ".zepto", ".odin", ".osiris", ".thor", ".aesir", ".shit",
    ".sage", ".globe", ".dharma", ".arena", ".java", ".onion",
    ".fucked", ".lol", ".zzzzz", ".exx", ".vvv", ".ttt",
}

RANSOM_NOTE_NAMES = [
    "README.txt", "HOW_TO_DECRYPT.txt", "HELP_DECRYPT.html",
    "DECRYPT_INSTRUCTIONS.txt", "YOUR_FILES_ARE_ENCRYPTED.txt",
    "RECOVERY.txt", "RESTORE_FILES.txt", "HOW_TO_RECOVER.txt",
    "RANSOM.txt", "_Locky_recover_instructions.txt",
    "Help Restore Your Files.txt", "@Please_Read_Me@.txt",
]

def scan_ransomware_indicators(folder: str, progress_cb=None) -> dict:
    """Scan folder for ransomware indicators."""
    hits       = []
    enc_count  = 0
    note_count = 0
    total      = 0

    try:
        for root, dirs, files in os.walk(folder):
            # Skip system dirs
            dirs[:] = [d for d in dirs if d not in
                       ("Windows", "System32", "$Recycle.Bin", "AppData")]
            for fname in files:
                total += 1
                fpath  = os.path.join(root, fname)
                ext    = os.path.splitext(fname)[1].lower()
                fname_l = fname.lower()

                # Ransomware extension
                if ext in RANSOMWARE_EXTENSIONS:
                    enc_count += 1
                    hits.append({
                        "type": "ENCRYPTED_FILE",
                        "severity": "CRITICAL",
                        "path": fpath,
                        "detail": f"Known ransomware extension: {ext}",
                    })

                # Ransom note
                if any(note.lower() == fname_l for note in RANSOM_NOTE_NAMES):
                    note_count += 1
                    hits.append({
                        "type": "RANSOM_NOTE",
                        "severity": "CRITICAL",
                        "path": fpath,
                        "detail": "Ransom note detected!",
                    })

                if progress_cb and total % 100 == 0:
                    progress_cb(f"Scanned {total} files... ({enc_count} suspicious)")

                if total > 50000:  # safety limit
                    break

    except PermissionError:
        pass
    except Exception as e:
        logger.error(f"Ransomware scan error: {e}")

    risk = "CRITICAL" if (enc_count > 5 or note_count > 0) else \
           "HIGH" if enc_count > 0 else "LOW"

    return {
        "total_scanned": total,
        "encrypted_files": enc_count,
        "ransom_notes": note_count,
        "hits": hits[:100],
        "risk": risk,
        "verdict": "🚨 RANSOMWARE DETECTED!" if (enc_count > 5 or note_count > 0) else
                   "⚠ Suspicious files found" if enc_count > 0 else
                   "✓ No ransomware indicators found",
    }


# ══════════════════════════════════════════════════════════════════════════
# 5. Fake AP / Rogue WiFi Detector
# ══════════════════════════════════════════════════════════════════════════

def detect_rogue_ap() -> dict:
    """Detect potential rogue/evil-twin access points."""
    from wifi_scanner import full_wifi_scan
    result   = full_wifi_scan()
    networks = result.get("networks", [])
    alerts   = []

    # Group by SSID — same name, different BSSID = potential evil twin
    ssid_map = {}
    for net in networks:
        ssid = net.get("ssid", "")
        if ssid and ssid != "<Hidden>":
            if ssid not in ssid_map:
                ssid_map[ssid] = []
            ssid_map[ssid].append(net)

    for ssid, nets in ssid_map.items():
        if len(nets) > 1:
            alerts.append({
                "type":    "EVIL_TWIN",
                "severity":"HIGH",
                "ssid":    ssid,
                "count":   len(nets),
                "detail":  f"'{ssid}' broadcast by {len(nets)} different BSSIDs — possible Evil Twin!",
                "bssids":  [n.get("bssid","?") for n in nets],
            })

    # Open networks
    for net in networks:
        if net.get("security_key") == "OPEN":
            alerts.append({
                "type":    "OPEN_NETWORK",
                "severity":"HIGH",
                "ssid":    net.get("ssid","?"),
                "detail":  f"Open (no encryption) network — MITM trivial",
                "bssids":  [net.get("bssid","?")],
            })

    # WEP networks
    for net in networks:
        if net.get("security_key") == "WEP":
            alerts.append({
                "type":    "WEP_NETWORK",
                "severity":"CRITICAL",
                "ssid":    net.get("ssid","?"),
                "detail":  "WEP encryption — crackable in under 60 seconds",
                "bssids":  [net.get("bssid","?")],
            })

    return {
        "total_networks": len(networks),
        "alerts":        alerts,
        "evil_twin_count": sum(1 for a in alerts if a["type"] == "EVIL_TWIN"),
        "risk":   "CRITICAL" if any(a["severity"]=="CRITICAL" for a in alerts) else
                  "HIGH"     if alerts else "LOW",
        "networks": networks,
    }


# ══════════════════════════════════════════════════════════════════════════
# 6. Keylogger Activity Scanner
# ══════════════════════════════════════════════════════════════════════════

KEYLOGGER_PROCESS_NAMES = [
    "keylogger", "keycapture", "keystroke", "spyware", "ardamax",
    "refog", "revealer", "actual keylogger", "perfect keylogger",
    "elite keylogger", "spyrix", "kidlogger", "kgb spy",
    "winspy", "win-spy", "stealth keylogger",
]

KEYLOGGER_REGISTRY_KEYS = [
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
]

KEYLOGGER_FILE_PATTERNS = [
    "keylog", "keystroke", "kgb_", "ardamax", "refog", "spyrix",
]

def scan_keylogger_indicators() -> dict:
    """Scan for keylogger indicators in processes, registry, startup."""
    hits = []

    # 1. Check running processes
    procs_out = _run(["tasklist", "/FO", "CSV", "/NH"])
    for line in procs_out.splitlines():
        parts = line.strip('"').split('","')
        if parts:
            proc_name = parts[0].lower()
            for kw in KEYLOGGER_PROCESS_NAMES:
                if kw in proc_name:
                    hits.append({
                        "type":     "PROCESS",
                        "severity": "CRITICAL",
                        "name":     parts[0],
                        "detail":   f"Known keylogger process: {parts[0]}",
                    })

    # 2. Check startup registry entries
    for reg_key in KEYLOGGER_REGISTRY_KEYS:
        out = _run(["reg", "query", reg_key])
        for line in out.splitlines():
            line_l = line.lower()
            for kw in KEYLOGGER_FILE_PATTERNS:
                if kw in line_l:
                    hits.append({
                        "type":     "REGISTRY",
                        "severity": "HIGH",
                        "name":     line.strip(),
                        "detail":   f"Suspicious startup entry: {line.strip()[:60]}",
                    })

    # 3. Check for suspicious DLLs hooked into processes (SetWindowsHookEx)
    hooks_out = _run(["wmic", "process", "get", "name,executablepath"])
    for line in hooks_out.splitlines():
        line_l = line.lower()
        for kw in KEYLOGGER_FILE_PATTERNS:
            if kw in line_l:
                hits.append({
                    "type":     "FILE",
                    "severity": "HIGH",
                    "name":     line.strip(),
                    "detail":   f"Suspicious executable path: {line.strip()[:60]}",
                })

    risk = "CRITICAL" if any(h["severity"]=="CRITICAL" for h in hits) else \
           "HIGH"     if hits else "LOW"

    return {
        "hits":    hits[:50],
        "count":   len(hits),
        "risk":    risk,
        "verdict": "🚨 KEYLOGGER INDICATORS FOUND!" if hits else "✓ No keylogger indicators detected",
        "checked_at": datetime.now().strftime("%H:%M:%S"),
    }


# ══════════════════════════════════════════════════════════════════════════
# 7. Port Knocking Detector
# ══════════════════════════════════════════════════════════════════════════

def detect_port_knocking(interface_timeout=5) -> dict:
    """Detect port knocking sequences by checking for unusual closed-port connections."""
    # Check recent connection attempts in Windows firewall log
    log_path = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
    results  = {"sequences": [], "risk": "LOW", "verdict": ""}
    hits     = []

    if os.path.exists(log_path):
        try:
            with open(log_path, "r", errors="ignore") as f:
                lines = f.readlines()[-500:]  # last 500 lines
            drop_map = {}  # src_ip -> [ports]
            for line in lines:
                if "DROP" in line or "DENY" in line:
                    parts = line.split()
                    if len(parts) >= 8:
                        src_ip   = parts[4] if len(parts) > 4 else ""
                        dst_port = parts[6] if len(parts) > 6 else ""
                        if src_ip and dst_port and dst_port.isdigit():
                            if src_ip not in drop_map:
                                drop_map[src_ip] = []
                            drop_map[src_ip].append(int(dst_port))
            # IPs hitting 3+ different closed ports = possible port knocking
            for ip, ports in drop_map.items():
                unique = sorted(set(ports))
                if len(unique) >= 3:
                    hits.append({
                        "src_ip": ip,
                        "ports":  unique[:10],
                        "count":  len(unique),
                        "detail": f"IP {ip} hit {len(unique)} different ports — possible port knocking",
                    })
        except Exception:
            pass

    # Fallback: check netstat for half-open connections
    netstat = _run(["netstat", "-n"])
    syn_counts = {}
    for line in netstat.splitlines():
        if "SYN" in line or "TIME_WAIT" in line:
            parts = line.split()
            if len(parts) >= 3:
                src = parts[1] if len(parts) > 1 else ""
                ip  = src.rsplit(":",1)[0] if ":" in src else src
                syn_counts[ip] = syn_counts.get(ip, 0) + 1

    for ip, count in syn_counts.items():
        if count >= 5:
            hits.append({
                "src_ip": ip,
                "ports":  [],
                "count":  count,
                "detail": f"IP {ip} has {count} SYN/TIME_WAIT connections",
            })

    risk = "HIGH" if hits else "LOW"
    return {
        "hits":    hits[:20],
        "count":   len(hits),
        "risk":    risk,
        "verdict": f"⚠ {len(hits)} potential port knocking sequence(s)" if hits else "✓ No port knocking detected",
        "checked_at": datetime.now().strftime("%H:%M:%S"),
    }


# ══════════════════════════════════════════════════════════════════════════
# 8. System Analytics
# ══════════════════════════════════════════════════════════════════════════

def get_disk_usage(path: str = None) -> list:
    """Get disk usage breakdown."""
    try:
        import psutil
        if path:
            usage = psutil.disk_usage(path)
            return [{"path": path, "total_gb": round(usage.total/1e9,1),
                     "used_gb": round(usage.used/1e9,1),
                     "free_gb": round(usage.free/1e9,1),
                     "pct": usage.percent}]
        partitions = []
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                partitions.append({
                    "path":     part.mountpoint,
                    "device":   part.device,
                    "fstype":   part.fstype,
                    "total_gb": round(usage.total/1e9, 1),
                    "used_gb":  round(usage.used/1e9,  1),
                    "free_gb":  round(usage.free/1e9,  1),
                    "pct":      usage.percent,
                })
            except Exception:
                pass
        return partitions
    except ImportError:
        out = _run(["wmic", "logicaldisk", "get",
                    "caption,size,freespace,filesystem"])
        disks = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3:
                try:
                    total = int(parts[2]) / 1e9
                    free  = int(parts[1]) / 1e9
                    used  = total - free
                    disks.append({"path": parts[0], "total_gb": round(total,1),
                                  "used_gb": round(used,1), "free_gb": round(free,1),
                                  "pct": round(used/total*100,1) if total else 0})
                except Exception:
                    pass
        return disks

def get_top_connections(limit: int = 15) -> list:
    """Get top active network connections."""
    try:
        import psutil
        conns = []
        for c in psutil.net_connections(kind="inet"):
            if c.status == "ESTABLISHED":
                try:
                    proc = psutil.Process(c.pid).name() if c.pid else "Unknown"
                except Exception:
                    proc = str(c.pid or "?")
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "--"
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "--"
                conns.append({"process": proc, "local": laddr,
                              "remote": raddr, "status": c.status, "pid": c.pid})
        return conns[:limit]
    except Exception:
        out = _run(["netstat", "-nob"] if os.name == "nt" else ["netstat", "-tnp"])
        conns = []
        for line in out.splitlines():
            if "ESTABLISHED" in line:
                parts = line.split()
                if len(parts) >= 4:
                    conns.append({"process": parts[-1] if len(parts) > 4 else "?",
                                  "local": parts[1], "remote": parts[2],
                                  "status": "ESTABLISHED", "pid": 0})
        return conns[:limit]

def get_battery_info() -> dict:
    """Get battery status."""
    try:
        import psutil
        bat = psutil.sensors_battery()
        if bat:
            return {
                "percent":    round(bat.percent, 1),
                "plugged":    bat.power_plugged,
                "secs_left":  bat.secsleft if bat.secsleft > 0 else None,
                "status":     "Charging" if bat.power_plugged else "On Battery",
                "time_left":  str(timedelta(seconds=bat.secsleft)) if bat.secsleft > 0 else "Calculating...",
                "available":  True,
            }
    except Exception:
        pass
    return {"available": False, "percent": 0, "status": "No battery / Desktop PC"}

def get_uptime() -> dict:
    """Get system uptime and boot time."""
    try:
        import psutil
        boot = psutil.boot_time()
        uptime_secs = time.time() - boot
        td = timedelta(seconds=int(uptime_secs))
        days    = td.days
        hours   = td.seconds // 3600
        minutes = (td.seconds % 3600) // 60
        return {
            "boot_time":   datetime.fromtimestamp(boot).strftime("%Y-%m-%d %H:%M:%S"),
            "uptime_str":  f"{days}d {hours}h {minutes}m",
            "uptime_secs": int(uptime_secs),
            "days": days, "hours": hours, "minutes": minutes,
        }
    except Exception:
        out = _run(["net", "statistics", "workstation"])
        for line in out.splitlines():
            if "Statistics since" in line:
                return {"uptime_str": line.replace("Statistics since","").strip(),
                        "boot_time": "--", "uptime_secs": 0}
        return {"uptime_str": "Unknown", "boot_time": "--", "uptime_secs": 0}

def get_login_attempts() -> list:
    """Get recent Windows login attempts from Event Log."""
    attempts = []
    try:
        # PowerShell to read Security event log (4624=success, 4625=failure)
        ps_cmd = (
            "Get-WinEvent -LogName Security -MaxEvents 50 "
            "-FilterHashtable @{Id=4624,4625} 2>$null | "
            "Select-Object TimeCreated,Id,Message | "
            "ConvertTo-Json -Compress"
        )
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15, creationflags=flags)
        if r.stdout.strip():
            try:
                events = json.loads(r.stdout)
                if isinstance(events, dict):
                    events = [events]
                for ev in events[:30]:
                    eid  = ev.get("Id", 0)
                    time_str = str(ev.get("TimeCreated",""))[:19]
                    msg  = ev.get("Message","")
                    # Extract account name from message
                    acct = ""
                    m = re.search(r"Account Name:\s+(\S+)", msg)
                    if m:
                        acct = m.group(1)
                    attempts.append({
                        "time":    time_str,
                        "type":    "SUCCESS" if eid == 4624 else "FAILURE",
                        "account": acct or "Unknown",
                        "event_id": eid,
                    })
            except Exception:
                pass
    except Exception:
        pass

    # Fallback entries if nothing found
    if not attempts:
        attempts = [{"time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                     "type": "INFO", "account": "Current user",
                     "event_id": 0,
                     "note": "Run as Administrator for full login history"}]
    return attempts


# ══════════════════════════════════════════════════════════════════════════
# 9. Hash Calculator
# ══════════════════════════════════════════════════════════════════════════

def calculate_hashes(text: str = "", filepath: str = "") -> dict:
    """Calculate MD5, SHA1, SHA256, SHA512 of text or file."""
    import hashlib
    results = {}
    try:
        if filepath and os.path.exists(filepath):
            with open(filepath, "rb") as f:
                data = f.read()
        else:
            data = text.encode("utf-8")
        for algo in ["md5", "sha1", "sha256", "sha512"]:
            h = hashlib.new(algo)
            h.update(data)
            results[algo] = h.hexdigest()
        results["size"] = len(data)
    except Exception as e:
        results["error"] = str(e)
    return results


# ══════════════════════════════════════════════════════════════════════════
# 10. Base64 Encoder/Decoder
# ══════════════════════════════════════════════════════════════════════════

def b64_encode(text: str) -> str:
    import base64
    return base64.b64encode(text.encode()).decode()

def b64_decode(text: str) -> str:
    import base64
    try:
        return base64.b64decode(text.encode()).decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error: {e}"


# ══════════════════════════════════════════════════════════════════════════
# 11. Subnet Calculator
# ══════════════════════════════════════════════════════════════════════════

def subnet_calc(ip_cidr: str) -> dict:
    """Calculate subnet details from IP/CIDR notation."""
    try:
        if "/" not in ip_cidr:
            ip_cidr += "/24"
        ip_str, cidr_str = ip_cidr.split("/")
        cidr = int(cidr_str)
        if not (0 <= cidr <= 32):
            return {"error": "CIDR must be 0-32"}

        # Convert IP to integer
        parts = [int(x) for x in ip_str.split(".")]
        ip_int = (parts[0]<<24)|(parts[1]<<16)|(parts[2]<<8)|parts[3]

        # Subnet mask
        mask_int  = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF
        net_int   = ip_int & mask_int
        bcast_int = net_int | (~mask_int & 0xFFFFFFFF)
        hosts     = max(0, bcast_int - net_int - 1)

        def int_to_ip(n):
            return ".".join(str((n >> s) & 0xFF) for s in [24,16,8,0])

        return {
            "ip":           ip_str,
            "cidr":         cidr,
            "network":      int_to_ip(net_int),
            "broadcast":    int_to_ip(bcast_int),
            "subnet_mask":  int_to_ip(mask_int),
            "first_host":   int_to_ip(net_int + 1),
            "last_host":    int_to_ip(bcast_int - 1),
            "total_hosts":  2 ** (32 - cidr),
            "usable_hosts": hosts,
            "ip_class":     "A" if parts[0] < 128 else "B" if parts[0] < 192 else "C",
            "is_private":   (parts[0]==10 or
                            (parts[0]==172 and 16<=parts[1]<=31) or
                            (parts[0]==192 and parts[1]==168)),
        }
    except Exception as e:
        return {"error": str(e)}
