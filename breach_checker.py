"""
breach_checker.py - Dark Web Data Breach Checker  v8.0
HaveIBeenPwned API v3 use karta hai email breach check ke liye.
Password check: k-anonymity model (safe — full hash never sent).
"""
import hashlib, urllib.request, urllib.error, json, logging, time
logger = logging.getLogger(__name__)

HIBP_EMAIL_URL  = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
HIBP_PWNED_URL  = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_USER_AGENT = "FYP-VulnAssessment-v8"

def check_email(email: str, api_key: str = "") -> dict:
    """
    Check if an email was found in known data breaches.
    api_key: HIBP v3 API key (optional — returns limited info without key).
    Returns: {found: bool, breaches: list, breach_count: int, error: str}
    """
    try:
        url = HIBP_EMAIL_URL.format(email=urllib.parse.quote(email))
        req = urllib.request.Request(url, headers={
            "User-Agent": HIBP_USER_AGENT,
            "hibp-api-key": api_key,
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            breaches = []
            for b in data:
                breaches.append({
                    "name":         b.get("Name",""),
                    "domain":       b.get("Domain",""),
                    "date":         b.get("BreachDate",""),
                    "pwn_count":    b.get("PwnCount",0),
                    "data_classes": b.get("DataClasses",[]),
                    "is_sensitive": b.get("IsSensitive",False),
                    "description":  b.get("Description","")[:200],
                })
            return {"found":True,"breaches":breaches,
                    "breach_count":len(breaches),"error":""}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"found":False,"breaches":[],"breach_count":0,"error":""}
        elif e.code == 401:
            return {"found":False,"breaches":[],"breach_count":0,
                    "error":"API key required. Get free key at haveibeenpwned.com"}
        elif e.code == 429:
            return {"found":False,"breaches":[],"breach_count":0,
                    "error":"Rate limited — wait 60 seconds and try again"}
        else:
            return {"found":False,"breaches":[],"breach_count":0,"error":f"HTTP {e.code}"}
    except Exception as e:
        return {"found":False,"breaches":[],"breach_count":0,"error":str(e)}


def check_password_pwned(password: str) -> dict:
    """
    Check if password appears in breach databases.
    Uses k-anonymity: only first 5 chars of SHA1 hash sent to API.
    Full password or full hash NEVER leaves your machine.
    Returns: {pwned: bool, count: int, error: str}
    """
    try:
        import urllib.parse
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]
        url = HIBP_PWNED_URL.format(prefix=prefix)
        req = urllib.request.Request(url, headers={"User-Agent": HIBP_USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
        for line in body.splitlines():
            h, _, cnt = line.partition(":")
            if h.strip() == suffix:
                return {"pwned":True,"count":int(cnt.strip()),"error":""}
        return {"pwned":False,"count":0,"error":""}
    except Exception as e:
        return {"pwned":False,"count":0,"error":str(e)}


def check_multiple_emails(emails: list, api_key: str = "") -> list:
    """Check list of emails with 1.5s delay between requests (HIBP rate limit)."""
    results = []
    for i, email in enumerate(emails):
        result = check_email(email.strip(), api_key)
        result["email"] = email
        results.append(result)
        if i < len(emails)-1:
            time.sleep(1.5)
    return results

def get_latest_breaches(limit: int = 10) -> list:
    """Get latest breaches from HIBP public API — no key needed."""
    import urllib.request, json
    try:
        url = "https://haveibeenpwned.com/api/v3/latestbreach"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "FYP-SecuritySuite/9.0")
        with urllib.request.urlopen(req, timeout=8) as resp:
            breach = json.loads(resp.read())
            return [breach] if breach else []
    except Exception:
        # Fallback: return well-known recent breaches
        return [
            {"Name":"RockYou2024","BreachDate":"2024-07-04","PwnCount":9948575157,
             "Description":"10 billion passwords leaked — largest in history","DataClasses":["Passwords"]},
            {"Name":"Trello","BreachDate":"2024-01-22","PwnCount":15115516,
             "Description":"Trello user data exposed via public API","DataClasses":["Email addresses","Usernames"]},
            {"Name":"AT&T","BreachDate":"2024-03-30","PwnCount":73481539,
             "Description":"AT&T customer data leaked on dark web","DataClasses":["Phone numbers","SSNs","Passcodes"]},
            {"Name":"Ticketmaster","BreachDate":"2024-05-20","PwnCount":560000000,
             "Description":"560M Ticketmaster records stolen by ShinyHunters","DataClasses":["Names","Emails","Cards"]},
            {"Name":"MOVEit","BreachDate":"2023-06-01","PwnCount":77000000,
             "Description":"MOVEit Transfer zero-day — 2,000+ orgs affected","DataClasses":["Names","SSNs","Emails"]},
        ][:limit]
