"""
darkweb_monitor.py  -  Dark Web Keyword Monitor
Monitors paste sites and leak forums for custom keywords (email, company name etc)
Uses public paste monitoring APIs — no Tor needed
"""
import urllib.request, urllib.parse, json, threading, time, hashlib, os, re
from datetime import datetime

MONITOR_FILE = "darkweb_alerts.json"
KEYWORDS_FILE = "darkweb_keywords.json"

# Public paste/leak monitoring sources (no auth needed)
PASTE_SOURCES = [
    ("PasteBin Recent",  "https://scrape.pastebin.com/api_scraping.php?limit=30"),
]

def load_keywords() -> list:
    if not os.path.exists(KEYWORDS_FILE): return []
    try:
        with open(KEYWORDS_FILE) as f: return json.load(f)
    except Exception: return []

def save_keywords(keywords: list):
    with open(KEYWORDS_FILE, "w") as f: json.dump(keywords, f)

def load_alerts() -> list:
    if not os.path.exists(MONITOR_FILE): return []
    try:
        with open(MONITOR_FILE) as f: return json.load(f)
    except Exception: return []

def save_alerts(alerts: list):
    try:
        with open(MONITOR_FILE, "w") as f: json.dump(alerts[-500:], f)
    except Exception: pass

THREAT_KEYWORDS_BUILTIN = [
    "password leaked", "credentials dump", "database breach",
    "email dump", "combo list", "stealer log", "rdp access",
    "shell access", "admin credentials", "zero day exploit",
]

def check_hibp_domain(domain: str) -> list:
    """Check if domain appears in HIBP breaches."""
    try:
        url = f"https://haveibeenpwned.com/api/v3/breaches"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "FYP-DarkWebMonitor/8.0")
        with urllib.request.urlopen(req, timeout=8) as resp:
            breaches = json.loads(resp.read())
            domain_l = domain.lower()
            matches = [b for b in breaches if domain_l in b.get("Domain","").lower()]
            return matches[:10]
    except Exception:
        return []

def search_paste_for_keywords(content: str, keywords: list) -> list:
    """Search paste content for keywords. Returns list of matches."""
    matches = []
    content_l = content.lower()
    for kw in keywords:
        if kw.lower() in content_l:
            # Find surrounding context
            idx = content_l.find(kw.lower())
            ctx = content[max(0,idx-50):idx+100].strip()
            ctx = re.sub(r'\s+', ' ', ctx)
            matches.append({"keyword": kw, "context": ctx[:150]})
    return matches

class DarkWebMonitor:
    def __init__(self, alert_callback=None, check_interval=300):
        self.cb       = alert_callback
        self.interval = check_interval  # 5 minutes default
        self.running  = False
        self._thread  = None
        self._seen    = set()  # seen paste keys
        self.alerts   = load_alerts()
        self.keywords = load_keywords()
        self.stats    = {"pastes_checked": 0, "alerts_found": 0, "last_check": "Never"}

    def add_keyword(self, kw: str):
        kw = kw.strip().lower()
        if kw and kw not in self.keywords:
            self.keywords.append(kw)
            save_keywords(self.keywords)
            return True
        return False

    def remove_keyword(self, kw: str):
        self.keywords = [k for k in self.keywords if k != kw]
        save_keywords(self.keywords)

    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self): self.running = False

    def manual_check(self) -> list:
        """Run one check immediately. Returns new alerts."""
        return self._do_check()

    def _loop(self):
        while self.running:
            self._do_check()
            for _ in range(self.interval):
                if not self.running: break
                time.sleep(1)

    def _do_check(self) -> list:
        if not self.keywords:
            return []
        new_alerts = []
        self.stats["last_check"] = datetime.now().strftime("%H:%M:%S")

        # Check each source
        for source_name, url in PASTE_SOURCES:
            try:
                req = urllib.request.Request(url)
                req.add_header("User-Agent", "FYP-DarkWebMonitor/8.0")
                with urllib.request.urlopen(req, timeout=10) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore")
                    try:
                        pastes = json.loads(raw)
                    except Exception:
                        continue

                    for paste in pastes[:30]:
                        paste_key = paste.get("key","")
                        if not paste_key or paste_key in self._seen:
                            continue
                        self._seen.add(paste_key)
                        self.stats["pastes_checked"] += 1

                        # Check title first (fast)
                        title = paste.get("title","") + " " + paste.get("syntax","")
                        title_matches = search_paste_for_keywords(title, self.keywords)

                        # If title matches or contains threat keyword, fetch content
                        content_matches = []
                        if title_matches or any(t in title.lower() for t in THREAT_KEYWORDS_BUILTIN[:5]):
                            try:
                                paste_url = f"https://scrape.pastebin.com/api_scrape_item.php?i={paste_key}"
                                cr = urllib.request.Request(paste_url)
                                cr.add_header("User-Agent","FYP-DarkWebMonitor/8.0")
                                with urllib.request.urlopen(cr, timeout=5) as cr_resp:
                                    content = cr_resp.read().decode("utf-8", errors="ignore")[:5000]
                                    content_matches = search_paste_for_keywords(content, self.keywords)
                            except Exception:
                                pass

                        all_matches = title_matches + content_matches
                        if all_matches:
                            alert = {
                                "id":       paste_key,
                                "source":   source_name,
                                "title":    paste.get("title","Untitled")[:60],
                                "url":      f"https://pastebin.com/{paste_key}",
                                "matches":  all_matches,
                                "keywords": [m["keyword"] for m in all_matches],
                                "severity": "HIGH" if len(all_matches) > 2 else "MEDIUM",
                                "time":     datetime.now().strftime("%Y-%m-%d %H:%M"),
                            }
                            self.alerts.insert(0, alert)
                            new_alerts.append(alert)
                            self.stats["alerts_found"] += 1
                            if self.cb: self.cb(alert)

            except Exception:
                pass  # API may be unavailable

        save_alerts(self.alerts)
        return new_alerts

    def get_alerts(self) -> list:
        return self.alerts[:100]

    def clear_alerts(self):
        self.alerts = []; save_alerts([])
