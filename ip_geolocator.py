"""
ip_geolocator.py  -  IP Geolocation Tracker
Looks up IP location using free APIs — no key needed for basic use
"""
import urllib.request, json, socket, logging
from datetime import datetime

logger = logging.getLogger(__name__)

APIS = [
    "http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,reverse,proxy,hosting",
    "https://ipapi.co/{}/json/",
]

def lookup_ip(ip: str) -> dict:
    """Look up geolocation for an IP address."""
    ip = ip.strip()
    if not ip:
        return {"error": "Empty IP"}

    # Validate
    try:
        socket.inet_aton(ip)
    except socket.error:
        try:
            ip = socket.gethostbyname(ip)  # try hostname resolution
        except Exception:
            return {"error": f"Invalid IP/hostname: {ip}"}

    # Private IP check
    private_ranges = [
        ("10.",), ("192.168.",), ("172.16.","172.17.","172.18.","172.19.",
         "172.20.","172.21.","172.22.","172.23.","172.24.","172.25.",
         "172.26.","172.27.","172.28.","172.29.","172.30.","172.31."),
        ("127.",), ("0.",),
    ]
    for ranges in private_ranges:
        if any(ip.startswith(r) for r in ranges):
            return {
                "ip": ip, "country": "Private Network", "countryCode": "LAN",
                "city": "Local", "regionName": "LAN",
                "lat": 0, "lon": 0, "isp": "Local Network",
                "is_private": True, "proxy": False,
                "threat_level": "LOW", "note": "Private/local IP — not routable on internet"
            }

    # Try APIs
    for api_url in APIS:
        try:
            url = api_url.format(ip)
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "FYP-SecuritySuite/8.0")
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())

            if data.get("status") == "fail":
                continue

            # Normalize fields across APIs
            result = {
                "ip":          ip,
                "country":     data.get("country") or data.get("country_name","Unknown"),
                "countryCode": data.get("countryCode") or data.get("country_code","??"),
                "region":      data.get("regionName") or data.get("region","Unknown"),
                "city":        data.get("city","Unknown"),
                "lat":         data.get("lat") or data.get("latitude", 0),
                "lon":         data.get("lon") or data.get("longitude", 0),
                "isp":         data.get("isp") or data.get("org","Unknown"),
                "org":         data.get("org",""),
                "asn":         data.get("as",""),
                "proxy":       data.get("proxy", False),
                "hosting":     data.get("hosting", False),
                "is_private":  False,
                "checked_at":  datetime.now().strftime("%H:%M:%S"),
            }

            # Threat assessment
            threat = "LOW"
            notes  = []
            # High-risk countries (cyber threat intelligence)
            high_risk_cc = {"KP","RU","CN","IR","NG","RO","UA"}  # known APT origins
            if result["countryCode"] in high_risk_cc:
                threat = "HIGH"
                notes.append(f"High-risk country: {result['country']}")
            if result.get("proxy"):
                threat = "HIGH"
                notes.append("VPN/Proxy detected — real origin hidden")
            if result.get("hosting"):
                notes.append("Hosting/datacenter IP — possible bot/scanner")
                if threat == "LOW": threat = "MEDIUM"

            result["threat_level"] = threat
            result["notes"]        = notes
            return result

        except Exception as e:
            logger.debug(f"Geo API {api_url}: {e}")
            continue

    return {"ip": ip, "error": "Could not look up IP — check internet connection",
            "country":"Unknown","city":"Unknown","lat":0,"lon":0,"threat_level":"UNKNOWN"}

def batch_lookup(ips: list) -> list:
    """Look up multiple IPs."""
    return [lookup_ip(ip) for ip in ips[:20]]  # max 20

def get_my_ip() -> str:
    """Get public IP of this machine."""
    try:
        req = urllib.request.Request("https://api.ipify.org")
        req.add_header("User-Agent", "FYP-SecuritySuite/8.0")
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close()
            return ip
        except Exception:
            return "Unknown"
