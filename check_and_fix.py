"""
check_and_fix.py  -  FYP Auto-Repair Tool v9.0
Run this ONCE to fix all missing classes/functions in your MyFYP folder.
Usage:  python check_and_fix.py
"""
import os, sys, ast, re

FOLDER = os.path.dirname(os.path.abspath(__file__))

# ── Color output ──────────────────────────────────────────────────────────
def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"

print(cyan("\n" + "="*60))
print(cyan("  FYP AUTO-REPAIR TOOL v9.0"))
print(cyan("="*60 + "\n"))

fixes_applied = 0

def fix_file(filename, check_for, append_code):
    global fixes_applied
    path = os.path.join(FOLDER, filename)
    if not os.path.exists(path):
        print(red(f"  [MISSING FILE] {filename} — skipping"))
        return
    with open(path, 'r', encoding='utf-8') as f:
        src = f.read()
    missing = [name for name in check_for
               if f'def {name}' not in src and f'class {name}' not in src
               and f'{name} =' not in src]
    if not missing:
        print(green(f"  [OK] {filename}"))
        return
    print(yellow(f"  [FIXING] {filename} — adding: {missing}"))
    with open(path, 'a', encoding='utf-8') as f:
        f.write('\n\n' + append_code)
    fixes_applied += 1
    print(green(f"  [FIXED] {filename}"))

# ══════════════════════════════════════════════════════════════════════════
print(cyan("Checking module files...\n"))

# ── wifi_scanner.py ───────────────────────────────────────────────────────
fix_file('wifi_scanner.py', ['WiFiScanner'], '''
class WiFiScanner:
    """Wrapper class for backward compatibility."""
    def scan(self):
        return full_wifi_scan().get("networks", [])
    def get_adapter_info(self):
        import subprocess
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            r = subprocess.run(["netsh","wlan","show","interfaces"],
                capture_output=True, text=True, timeout=10, creationflags=flags)
            info = {"name":"WiFi","ssid":"Unknown","signal":"--"}
            for line in r.stdout.splitlines():
                if "SSID" in line and "BSSID" not in line and ":" in line:
                    info["ssid"] = line.split(":",1)[1].strip()
                elif "Signal" in line and ":" in line:
                    info["signal"] = line.split(":",1)[1].strip()
            return info
        except Exception:
            return {"name":"WiFi","ssid":"Unknown","signal":"--"}
''')

# ── breach_checker.py ─────────────────────────────────────────────────────
fix_file('breach_checker.py', ['get_latest_breaches'], '''
def get_latest_breaches(limit: int = 10) -> list:
    """Get latest data breaches — HIBP API with offline fallback."""
    import urllib.request, json
    try:
        req = urllib.request.Request("https://haveibeenpwned.com/api/v3/latestbreach")
        req.add_header("User-Agent", "FYP-SecuritySuite/9.0")
        with urllib.request.urlopen(req, timeout=8) as r:
            b = json.loads(r.read())
            return [b] if b else []
    except Exception:
        return [
            {"Name":"RockYou2024","BreachDate":"2024-07-04","PwnCount":9948575157,
             "Description":"10 billion passwords — largest breach in history",
             "DataClasses":["Passwords"]},
            {"Name":"AT&T","BreachDate":"2024-03-30","PwnCount":73481539,
             "Description":"AT&T 73M customer records leaked on dark web",
             "DataClasses":["Phone numbers","SSNs","Passcodes"]},
            {"Name":"Ticketmaster","BreachDate":"2024-05-20","PwnCount":560000000,
             "Description":"560M records stolen by ShinyHunters group",
             "DataClasses":["Names","Emails","Credit cards"]},
            {"Name":"Trello","BreachDate":"2024-01-22","PwnCount":15115516,
             "Description":"Public API exposed 15M user emails",
             "DataClasses":["Emails","Usernames"]},
            {"Name":"MOVEit","BreachDate":"2023-06-01","PwnCount":77000000,
             "Description":"MOVEit Transfer zero-day hit 2000+ organizations",
             "DataClasses":["Names","SSNs","Emails"]},
        ][:limit]
''')

# ── ctf_challenges.py ─────────────────────────────────────────────────────
fix_file('ctf_challenges.py', ['get_rank','get_solved_count','reset_progress'], '''
# ── Extended CTF functions ────────────────────────────────────────────────
_solved_set  = set()
_total_score = 0

def get_rank(pts: int) -> tuple:
    """Return (rank_title, color) based on points."""
    if pts >= 500: return ("⚡ ELITE HACKER",  "#FF2D55")
    if pts >= 300: return ("🔥 EXPERT",         "#FF8C42")
    if pts >= 150: return ("💡 INTERMEDIATE",   "#FFD60A")
    if pts >= 50:  return ("🌱 BEGINNER",        "#00D4FF")
    return ("👾 NOVICE", "#7BAFD4")

def get_solved_count() -> int:
    """Return number of solved challenges."""
    global _solved_set
    return len(_solved_set)

def reset_progress():
    """Reset all CTF progress."""
    global _solved_set, _total_score
    _solved_set  = set()
    _total_score = 0
''')

# ── scan_history.py ───────────────────────────────────────────────────────
fix_file('scan_history.py', ['ScanHistory'], '''
class ScanHistory:
    """Stores last 50 scans with JSON persistence."""
    import json, os
    FILE = "scan_history.json"
    def __init__(self):
        self.history = self._load()
    def _load(self):
        import json, os
        if not os.path.exists(self.FILE): return []
        try:
            with open(self.FILE) as f: return json.load(f)
        except Exception: return []
    def add(self, entry: dict):
        import json
        self.history.insert(0, entry)
        self.history = self.history[:50]
        try:
            with open(self.FILE,"w") as f: json.dump(self.history, f)
        except Exception: pass
    def get_all(self): return self.history
    def clear(self):
        self.history = []
        import os
        try: os.remove(self.FILE)
        except Exception: pass
''')

# ── sys_monitor.py ────────────────────────────────────────────────────────
fix_file('sys_monitor.py', ['SystemMonitor'], '''
class SystemMonitor:
    """CPU/RAM/Disk/Network monitor using psutil."""
    def __init__(self, callback=None, interval=2):
        self.cb       = callback
        self.interval = interval
        self.running  = False
        self._thread  = None
    def start(self):
        import threading
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
    def stop(self): self.running = False
    def get_stats(self) -> dict:
        try:
            import psutil
            return {
                "cpu":  psutil.cpu_percent(interval=0.1),
                "ram":  psutil.virtual_memory().percent,
                "disk": psutil.disk_usage("/").percent,
                "net":  psutil.net_io_counters()._asdict(),
            }
        except ImportError:
            return {"cpu": 0, "ram": 0, "disk": 0, "net": {}}
    def _loop(self):
        import time
        while self.running:
            stats = self.get_stats()
            if self.cb: self.cb(stats)
            time.sleep(self.interval)
''')

# ── network_map.py ────────────────────────────────────────────────────────
fix_file('network_map.py', ['NetworkMapper'], '''
class NetworkMapper:
    """Subnet device discovery."""
    def scan_subnet(self, subnet: str = "", callback=None) -> list:
        import subprocess, socket, os
        devices = []
        try:
            if not subnet:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                parts    = local_ip.split(".")
                subnet   = f"{parts[0]}.{parts[1]}.{parts[2]}"
            flags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            for i in range(1, 20):
                ip = f"{subnet}.{i}"
                r  = subprocess.run(["ping","-n","1","-w","300",ip] if os.name=="nt"
                                    else ["ping","-c","1","-W","1",ip],
                                    capture_output=True, text=True,
                                    creationflags=flags, timeout=3)
                if r.returncode == 0:
                    try: host = socket.gethostbyaddr(ip)[0]
                    except Exception: host = ip
                    dev = {"ip":ip,"hostname":host,"status":"UP","mac":"--","vendor":"--"}
                    devices.append(dev)
                    if callback: callback(dev)
        except Exception: pass
        return devices
''')

# ── alert_system.py ───────────────────────────────────────────────────────
fix_file('alert_system.py', ['AlertSystem'], '''
class AlertSystem:
    """Background threat monitor — checks open ports every 30s."""
    CRITICAL_PORTS = [21,22,23,25,135,139,445,3389,5900]
    def __init__(self, alert_callback=None, interval=30):
        self.cb       = alert_callback
        self.interval = interval
        self.running  = False
        self._thread  = None
        self.alerts   = []
    def start(self):
        import threading
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
    def stop(self): self.running = False
    def _loop(self):
        import time
        while self.running:
            self._check()
            time.sleep(self.interval)
    def _check(self):
        import socket
        from datetime import datetime
        for port in self.CRITICAL_PORTS:
            try:
                s = socket.socket(); s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    alert = {"port":port,"level":"HIGH","time":datetime.now().strftime("%H:%M:%S"),
                             "msg":f"Port {port} is OPEN on localhost"}
                    self.alerts.insert(0, alert)
                    if self.cb: self.cb(alert)
                s.close()
            except Exception: pass
    def get_alerts(self): return self.alerts[:100]
    def clear(self): self.alerts = []
''')

# ── scheduler.py ─────────────────────────────────────────────────────────
fix_file('scheduler.py', ['ScanScheduler'], '''
class ScanScheduler:
    """Daily/weekly auto-scan scheduler."""
    import json, os
    FILE = "scan_schedule.json"
    def __init__(self, scan_callback=None):
        self.cb      = scan_callback
        self.running = False
        self._thread = None
        self.config  = self._load()
    def _load(self):
        import json, os
        if not os.path.exists(self.FILE): return {"enabled":False,"mode":"daily","time":"02:00"}
        try:
            with open(self.FILE) as f: return json.load(f)
        except Exception: return {"enabled":False,"mode":"daily","time":"02:00"}
    def save(self, config: dict):
        import json
        self.config = config
        with open(self.FILE,"w") as f: json.dump(config, f)
    def start(self):
        import threading
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
    def stop(self): self.running = False
    def _loop(self):
        import time
        from datetime import datetime
        while self.running:
            if self.config.get("enabled"):
                now = datetime.now().strftime("%H:%M")
                if now == self.config.get("time","02:00"):
                    if self.cb: self.cb(self.config.get("target","127.0.0.1"))
                    time.sleep(61)
            time.sleep(30)
    def get_config(self): return self.config
''')

# ── firewall_manager.py ───────────────────────────────────────────────────
fix_file('firewall_manager.py', ['FirewallManager'], '''
class FirewallManager:
    """Windows Firewall manager using netsh."""
    def get_status(self) -> dict:
        import subprocess, os
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            r = subprocess.run(["netsh","advfirewall","show","allprofiles"],
                capture_output=True, text=True, creationflags=flags, timeout=10)
            enabled = "ON" in r.stdout.upper()
            return {"enabled": enabled, "output": r.stdout[:500]}
        except Exception as e: return {"enabled": False, "output": str(e)}
    def get_all_rules(self) -> list:
        import subprocess, os, re
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            r = subprocess.run(["netsh","advfirewall","firewall","show","rule","name=all"],
                capture_output=True, text=True, creationflags=flags, timeout=15)
            rules = []; current = {}
            for line in r.stdout.splitlines():
                if line.startswith("Rule Name:"): 
                    if current: rules.append(current)
                    current = {"name": line.split(":",1)[1].strip()}
                elif ":" in line and current:
                    k,v = line.split(":",1)
                    current[k.strip().lower()] = v.strip()
            if current: rules.append(current)
            return rules[:100]
        except Exception: return []
    def enable(self) -> bool:
        import subprocess, os
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            r = subprocess.run(["netsh","advfirewall","set","allprofiles","state","on"],
                capture_output=True, text=True, creationflags=flags, timeout=10)
            return r.returncode == 0
        except Exception: return False
''')

# ── auto_fix.py ───────────────────────────────────────────────────────────
fix_file('auto_fix.py', ['AutoFixer'], '''
class AutoFixer:
    """One-click security fixes using netsh/reg commands."""
    FIXES = {
        "fw_enable":      ("Enable Windows Firewall",       ["netsh","advfirewall","set","allprofiles","state","on"]),
        "block_rdp":      ("Block RDP port 3389",            ["netsh","advfirewall","firewall","add","rule","name=Block_RDP","dir=in","action=block","protocol=TCP","localport=3389"]),
        "block_telnet":   ("Block Telnet port 23",           ["netsh","advfirewall","firewall","add","rule","name=Block_Telnet","dir=in","action=block","protocol=TCP","localport=23"]),
        "flush_dns":      ("Flush DNS cache",                ["ipconfig","/flushdns"]),
    }
    def apply_fix(self, fix_id: str) -> tuple:
        import subprocess, os
        fix = self.FIXES.get(fix_id)
        if not fix: return False, "Unknown fix"
        name, cmd = fix
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
            r = subprocess.run(cmd, capture_output=True, text=True,
                               creationflags=flags, timeout=15)
            return r.returncode==0, r.stdout + r.stderr
        except Exception as e: return False, str(e)
    def get_all_fixes(self) -> dict: return self.FIXES
''')

# ══════════════════════════════════════════════════════════════════════════
print(cyan("\n" + "="*60))
if fixes_applied == 0:
    print(green(f"  ALL FILES OK — no fixes needed!"))
else:
    print(green(f"  {fixes_applied} file(s) fixed successfully!"))
print(cyan("="*60))

# Final syntax check on main_app.py
main_path = os.path.join(FOLDER, 'main_app.py')
if os.path.exists(main_path):
    try:
        with open(main_path, encoding='utf-8') as f:
            ast.parse(f.read())
        print(green("\n  main_app.py syntax: OK ✓"))
    except SyntaxError as e:
        print(red(f"\n  main_app.py ERROR: line {e.lineno}: {e.msg}"))

print(cyan("\n  Run:  python main_app.py\n"))
