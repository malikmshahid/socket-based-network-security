"""
=============================================================================
security_news.py  –  Live Cybersecurity News Feed
=============================================================================
AI-Powered Vulnerability Assessment System  v8.0
Latest cybersecurity news fetch karta hai — CVE alerts, breach news, threats
Uses RSS feeds — no API key needed
=============================================================================
"""

import urllib.request
import re
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Free cybersecurity RSS feeds
RSS_FEEDS = [
    ("Krebs on Security",  "https://krebsonsecurity.com/feed/"),
    ("CISA Alerts",        "https://www.cisa.gov/news.xml"),
    ("Threatpost",         "https://threatpost.com/feed/"),
    ("The Hacker News",    "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer",   "https://www.bleepingcomputer.com/feed/"),
    ("CVE New This Week",  "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss-analyzed.xml"),
]

# Keyword tags for categorizing stories
THREAT_KEYWORDS = {
    "ransomware":   ("#FF2D55", "RANSOMWARE"),
    "critical":     ("#FF2D55", "CRITICAL"),
    "zero-day":     ("#FF2D55", "ZERO-DAY"),
    "zero day":     ("#FF2D55", "ZERO-DAY"),
    "breach":       ("#FF8C42", "BREACH"),
    "exploit":      ("#FF8C42", "EXPLOIT"),
    "vulnerability":("#FFD60A", "VULN"),
    "patch":        ("#00D4FF", "PATCH"),
    "update":       ("#00D4FF", "UPDATE"),
    "malware":      ("#FF8C42", "MALWARE"),
    "phishing":     ("#FF8C42", "PHISHING"),
    "ddos":         ("#FF8C42", "DDOS"),
    "backdoor":     ("#FF2D55", "BACKDOOR"),
    "cve":          ("#FFD60A", "CVE"),
}


def _fetch_rss(url: str, timeout: int = 8) -> str:
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "FYP-SecurityDashboard/8.0")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        logger.debug(f"RSS fetch error ({url}): {e}")
        return ""


def _parse_rss(xml: str, source: str, max_items: int = 8) -> list:
    """Parse RSS XML into list of article dicts."""
    items = []
    # Extract <item> blocks
    blocks = re.findall(r"<item>(.*?)</item>", xml, re.DOTALL)

    for block in blocks[:max_items]:
        title_m = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", block, re.DOTALL)
        link_m  = re.search(r"<link>(.*?)</link>", block, re.DOTALL)
        date_m  = re.search(r"<pubDate>(.*?)</pubDate>", block, re.DOTALL)
        desc_m  = re.search(r"<description>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</description>", block, re.DOTALL)

        title = (title_m.group(1).strip() if title_m else "Unknown").strip()
        link  = (link_m.group(1).strip()  if link_m  else "").strip()
        date  = (date_m.group(1).strip()  if date_m  else "").strip()[:20]
        desc  = (desc_m.group(1).strip()  if desc_m  else "").strip()

        # Clean HTML from description
        desc = re.sub(r"<[^>]+>", "", desc)[:200]

        # Tag by keywords
        title_lower = title.lower() + desc.lower()
        tag_color = "#7BAFD4"; tag_label = "NEWS"
        for kw, (color, label) in THREAT_KEYWORDS.items():
            if kw in title_lower:
                tag_color = color; tag_label = label
                break

        title = title[:100]
        if title:
            items.append({
                "title":     title,
                "link":      link,
                "date":      date,
                "desc":      desc,
                "source":    source,
                "tag_color": tag_color,
                "tag_label": tag_label,
                "fetched":   datetime.now().strftime("%H:%M"),
            })
    return items


def fetch_news(max_per_feed: int = 5) -> list:
    """
    Fetch latest cybersecurity news from multiple sources.
    Returns sorted list of news items.
    """
    all_items = []
    for source_name, url in RSS_FEEDS:
        try:
            xml   = _fetch_rss(url)
            items = _parse_rss(xml, source_name, max_per_feed)
            all_items.extend(items)
        except Exception as e:
            logger.debug(f"News fetch {source_name}: {e}")

    # If all feeds fail (no internet), return sample data
    if not all_items:
        all_items = _sample_news()

    return all_items


def _sample_news() -> list:
    """Sample news items when offline."""
    return [
        {"title": "WannaCry Still Active in 2024 — Thousands of Unpatched Systems",
         "source": "Sample", "date": "2024", "desc": "Despite patches being available for 7+ years, WannaCry continues to infect unpatched Windows machines.",
         "tag_color": "#FF2D55", "tag_label": "RANSOMWARE", "fetched": "offline", "link": ""},
        {"title": "CRITICAL: New Zero-Day in Windows Print Spooler Discovered",
         "source": "Sample", "date": "2024", "desc": "Security researchers discovered a new privilege escalation vulnerability in Windows Print Spooler service.",
         "tag_color": "#FF2D55", "tag_label": "ZERO-DAY", "fetched": "offline", "link": ""},
        {"title": "RDP Brute Force Attacks Hit Record 1.5 Million Per Day",
         "source": "Sample", "date": "2024", "desc": "Automated brute force tools targeting open RDP port 3389 have reached unprecedented levels globally.",
         "tag_color": "#FF8C42", "tag_label": "EXPLOIT", "fetched": "offline", "link": ""},
        {"title": "Microsoft Patches 6 Critical Vulnerabilities — Update Now",
         "source": "Sample", "date": "2024", "desc": "This month's Patch Tuesday includes fixes for 6 critical remote code execution vulnerabilities.",
         "tag_color": "#00D4FF", "tag_label": "PATCH", "fetched": "offline", "link": ""},
        {"title": "New Phishing Campaign Targets Microsoft 365 Users",
         "source": "Sample", "date": "2024", "desc": "Sophisticated phishing emails bypassing spam filters are stealing Office 365 credentials worldwide.",
         "tag_color": "#FF8C42", "tag_label": "PHISHING", "fetched": "offline", "link": ""},
    ]
