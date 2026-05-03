"""
report_card.py - Security Report Card Generator  v8.0
Scan results se A/B/C/D/F grade card banata hai — printable.
"""
from datetime import datetime

GRADE_TABLE = [
    (90, "A+", "#00FF88", "EXCELLENT",  "Outstanding security posture. Military-grade protection."),
    (80, "A",  "#00CC66", "VERY GOOD",  "Strong security. Minor improvements possible."),
    (70, "B",  "#00D4FF", "GOOD",       "Good security with some gaps to address."),
    (60, "C",  "#FFD60A", "AVERAGE",    "Average security. Multiple issues need attention."),
    (50, "D",  "#FF8C42", "POOR",       "Poor security posture. Significant vulnerabilities present."),
    (30, "F",  "#FF2D55", "FAILING",    "Critical security failures. Immediate action required."),
    ( 0, "F-", "#CC0020", "CRITICAL",   "SEVERE: System is critically vulnerable. Halt operations."),
]

CATEGORIES = [
    ("open_ports",    "Port Security",      25),
    ("firewall",      "Firewall",           25),
    ("os_updates",    "Patch Management",   20),
    ("antivirus",     "Endpoint Protection",20),
    ("critical_ports","Critical Exposure",  10),
]


def _letter_grade(score: int) -> tuple:
    for threshold, letter, color, label, desc in GRADE_TABLE:
        if score >= threshold:
            return letter, color, label, desc
    return "F-", "#CC0020", "CRITICAL", "SEVERE vulnerabilities"


def _category_grade(score: int) -> tuple:
    """Convert 0-100 risk score to category grade (invert — lower risk = better grade)."""
    safety = max(0, 100 - score)
    return _letter_grade(safety)


def generate_report_card(scan_results: dict, risk_result: dict) -> dict:
    score  = risk_result.get("risk_score", 0)
    sub    = risk_result.get("sub_scores", {})
    level  = risk_result.get("risk_level", "LOW")
    recs   = risk_result.get("recommendations", [])

    safety_score = max(0, 100 - score)
    overall_letter, overall_color, overall_label, overall_desc = _letter_grade(safety_score)

    categories_detail = []
    for key, label, weight in CATEGORIES:
        risk_val = sub.get(key, 0)
        safety   = max(0, 100 - risk_val)
        letter, color, cat_label, _ = _category_grade(risk_val)
        categories_detail.append({
            "key":    key,
            "label":  label,
            "weight": weight,
            "safety": safety,
            "risk":   risk_val,
            "grade":  letter,
            "color":  color,
            "status": cat_label,
        })

    target_ip = scan_results.get("target_ip","Unknown")
    hostname  = scan_results.get("system_info",{}).get("hostname","Unknown")
    fw        = scan_results.get("firewall_status","Unknown")
    av        = scan_results.get("antivirus_status","Unknown")
    upd       = scan_results.get("os_update_status","Unknown")
    ports     = scan_results.get("open_ports",[])
    crit_ports= scan_results.get("critical_ports_open",[])

    strengths = []
    weaknesses = []
    if "ENABLED" in fw.upper():    strengths.append("✓ Firewall is active")
    else:                           weaknesses.append("✗ Firewall is disabled")
    if "ACTIVE" in av.upper():     strengths.append("✓ Antivirus is running")
    else:                           weaknesses.append("✗ Antivirus inactive")
    if "UP-TO-DATE" in upd.upper() or "UP_TO_DATE" in upd.upper():
        strengths.append("✓ OS patches are current")
    else:
        weaknesses.append("✗ OS updates pending")
    if not crit_ports:              strengths.append("✓ No critical ports exposed")
    else:
        for p in crit_ports:
            weaknesses.append(f"✗ Critical port {p} open")
    if len(ports) == 0:             strengths.append("✓ No open ports detected")

    priority_recs = [r for r in recs if r.get("priority") in ("CRITICAL","HIGH")][:5]

    return {
        "overall_score":   safety_score,
        "overall_grade":   overall_letter,
        "overall_color":   overall_color,
        "overall_label":   overall_label,
        "overall_desc":    overall_desc,
        "risk_score":      score,
        "risk_level":      level,
        "target_ip":       target_ip,
        "hostname":        hostname,
        "categories":      categories_detail,
        "strengths":       strengths,
        "weaknesses":      weaknesses,
        "top_recs":        priority_recs,
        "open_ports":      ports,
        "scan_date":       datetime.now().strftime("%Y-%m-%d %H:%M"),
    }
