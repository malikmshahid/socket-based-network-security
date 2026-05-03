"""
=============================================================================
threat_report_writer.py  –  AI Threat Report Writer
=============================================================================
AI-Powered Vulnerability Assessment System  v7.0
Scan results se automatically detailed professional prose report likhta hai.
Export to TXT / copy to clipboard.
=============================================================================
"""

from datetime import datetime
import socket


# ── Threat narrative templates ──────────────────────────────────────────────

_INTROS = {
    "CRITICAL": (
        "EXECUTIVE SUMMARY — CRITICAL RISK DETECTED\n"
        "This automated security assessment has identified a CRITICAL risk profile "
        "on the target system. Immediate remediation is strongly advised before this "
        "machine handles any sensitive data or remains connected to the wider network."
    ),
    "HIGH": (
        "EXECUTIVE SUMMARY — HIGH RISK DETECTED\n"
        "The assessment engine has flagged a HIGH risk configuration on the target "
        "system. Several significant vulnerabilities were found that could be "
        "exploited by a moderately skilled attacker. Prompt remediation is recommended."
    ),
    "MEDIUM": (
        "EXECUTIVE SUMMARY — MODERATE RISK\n"
        "The target system shows a MEDIUM risk profile. While no single catastrophic "
        "vulnerability was found, the cumulative effect of the identified weaknesses "
        "increases the overall attack surface. Scheduled remediation is advised."
    ),
    "LOW": (
        "EXECUTIVE SUMMARY — LOW RISK\n"
        "The target system presents a LOW risk profile. Basic security controls appear "
        "to be in place. Continued maintenance and periodic reassessment are recommended "
        "to preserve this security posture."
    ),
}

_PORT_NARR = {
    445: ("SMB port 445 is open. This port was exploited by the WannaCry ransomware in 2017, "
          "infecting over 200,000 systems across 150 countries and causing approximately "
          "USD 4 billion in damages. The underlying exploit, EternalBlue (CVE-2017-0144), "
          "was developed by the NSA and later leaked by the Shadow Brokers group. "
          "This port should be blocked at the firewall immediately."),
    3389: ("RDP port 3389 is open. Remote Desktop Protocol is one of the most heavily "
           "targeted attack vectors in the wild. The BlueKeep vulnerability (CVE-2019-0708) "
           "allowed unauthenticated remote code execution — over one million exposed systems "
           "were identified before patching. Additionally, brute-force attacks against "
           "RDP credentials number in the hundreds of millions daily. If RDP is not "
           "required, it should be disabled; if required, it must be placed behind a VPN."),
    23:   ("Telnet port 23 is open. Telnet transmits all data — including usernames and "
           "passwords — in plain text. Any attacker with network access can capture these "
           "credentials using freely available tools such as Wireshark. Telnet has been "
           "deprecated for over two decades; SSH should be used exclusively."),
    21:   ("FTP port 21 is open. Like Telnet, FTP transmits credentials in clear text "
           "and is trivially intercepted. SFTP or FTPS should replace any FTP services."),
    5900: ("VNC port 5900 is open. VNC provides full graphical desktop access. "
           "Thousands of unprotected VNC endpoints are indexed by Shodan at any given moment. "
           "If VNC is required, it must be tunnelled through an encrypted channel."),
    3306: ("MySQL port 3306 is open and reachable on the network. Database services "
           "should never be exposed directly to the network; they should be bound to "
           "localhost and accessed only through the application layer."),
    135:  ("RPC port 135 is open. Windows RPC was exploited by the Blaster worm "
           "(MS03-026) to infect millions of systems. It should not be reachable externally."),
}


def _fw_sentence(status: str) -> str:
    s = status.lower()
    if "enabled" in s or "on" in s:
        return "The Windows Firewall is enabled, providing a basic network barrier."
    if "disabled" in s or "off" in s:
        return ("The Windows Firewall is DISABLED. This is a critical misconfiguration: "
                "the system is receiving inbound connections on all ports with no filtering "
                "whatsoever. The firewall must be re-enabled immediately "
                "(netsh advfirewall set allprofiles state on).")
    return "The firewall status could not be determined conclusively."


def _av_sentence(status: str) -> str:
    s = status.lower()
    if "active" in s or "enabled" in s or "running" in s:
        return "Windows Defender (antivirus) is active and providing real-time protection."
    if "inactive" in s or "disabled" in s or "stopped" in s:
        return ("Antivirus / Windows Defender is NOT active. Without real-time protection "
                "the system is vulnerable to malware, ransomware, and trojans. "
                "Defender should be re-enabled: sc start WinDefend.")
    return "Antivirus status is inconclusive; manual verification is recommended."


def _upd_sentence(status: str) -> str:
    s = status.lower()
    if "up-to-date" in s or "up_to_date" in s or "updated" in s:
        return ("The operating system appears to be up-to-date. "
                "Applying patches promptly remains the single most effective defence "
                "against known exploits such as EternalBlue.")
    if "available" in s or "pending" in s:
        return ("Pending OS updates were detected. Unpatched systems are primary targets: "
                "WannaCry exclusively infected machines that had not installed MS17-010, "
                "a patch that had been available for two months before the outbreak. "
                "Run wuauclt /updatenow to install available updates.")
    return "OS update status could not be fully verified."


def _score_narrative(score: int, level: str) -> str:
    if level == "CRITICAL":
        return (f"The composite risk score is {score}/100, placing this system in the "
                "CRITICAL category. A score in this range indicates that multiple severe "
                "vulnerabilities are present simultaneously, creating an attack surface "
                "that a skilled adversary could exploit with minimal effort.")
    if level == "HIGH":
        return (f"The composite risk score is {score}/100 (HIGH). "
                "Significant exposure exists; an attacker with moderate capability "
                "would likely succeed in gaining unauthorised access or disrupting services.")
    if level == "MEDIUM":
        return (f"The composite risk score is {score}/100 (MEDIUM). "
                "The system has partial protections in place but several gaps remain "
                "that collectively raise the risk above an acceptable threshold.")
    return (f"The composite risk score is {score}/100 (LOW). "
            "Core security controls appear to be functioning correctly.")


# ── Public function ──────────────────────────────────────────────────────────

def generate_threat_report(scan_results: dict, risk_result: dict) -> str:
    """
    Generate a full prose threat report from scan + risk data.
    Returns the report as a plain-text string.
    """
    score      = risk_result.get("risk_score", 0)
    level      = risk_result.get("risk_level", "LOW")
    sub        = risk_result.get("sub_scores", {})
    threats    = risk_result.get("threats", [])
    recs       = risk_result.get("recommendations", [])
    target_ip  = scan_results.get("target_ip", "Unknown")
    hostname   = scan_results.get("system_info", {}).get("hostname", "Unknown")
    fw         = scan_results.get("firewall_status", "Unknown")
    av         = scan_results.get("antivirus_status", "Unknown")
    upd        = scan_results.get("os_update_status", "Unknown")
    open_ports = scan_results.get("open_ports", [])
    crit_ports = scan_results.get("critical_ports_open", [])
    now        = datetime.now().strftime("%A, %d %B %Y  %H:%M:%S")

    lines = []
    sep   = "=" * 72
    thin  = "-" * 72

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        sep,
        "  AI-POWERED VULNERABILITY ASSESSMENT SYSTEM",
        "  AUTOMATED THREAT INTELLIGENCE REPORT",
        sep,
        f"  Date / Time  : {now}",
        f"  Target IP    : {target_ip}",
        f"  Hostname     : {hostname}",
        f"  Risk Level   : {level}",
        f"  Risk Score   : {score} / 100",
        sep, "",
    ]

    # ── Executive Summary ────────────────────────────────────────────────────
    lines += [
        "1.  EXECUTIVE SUMMARY",
        thin,
        _INTROS.get(level, _INTROS["LOW"]),
        "",
        _score_narrative(score, level),
        "",
    ]

    # ── Security Control Analysis ────────────────────────────────────────────
    lines += [
        "2.  SECURITY CONTROL ANALYSIS",
        thin,
        "2.1  Firewall",
        _fw_sentence(fw), "",
        "2.2  Antivirus / Endpoint Protection",
        _av_sentence(av), "",
        "2.3  Operating System Patch Status",
        _upd_sentence(upd), "",
    ]

    # ── Open Port Analysis ───────────────────────────────────────────────────
    lines += ["3.  OPEN PORT ANALYSIS", thin]
    if not open_ports:
        lines += ["No open ports were detected during this scan.", ""]
    else:
        lines += [
            f"{len(open_ports)} open port(s) discovered: "
            f"{', '.join(str(p) for p in sorted(open_ports))}",
            "",
        ]
        for port in sorted(open_ports):
            if port in _PORT_NARR:
                lines += [f"Port {port}:", _PORT_NARR[port], ""]
        if crit_ports:
            lines += [
                "CRITICAL PORTS SUMMARY:",
                (f"The following ports are classified as critical and represent "
                 f"immediate risk: {', '.join(str(p) for p in crit_ports)}."),
                "",
            ]

    # ── Risk Factor Breakdown ────────────────────────────────────────────────
    lines += ["4.  RISK FACTOR BREAKDOWN", thin]
    factor_map = [
        ("Open Ports",     "open_ports",    "25%"),
        ("Firewall",       "firewall",      "25%"),
        ("OS Updates",     "os_updates",    "20%"),
        ("Antivirus",      "antivirus",     "20%"),
        ("Critical Ports", "critical_ports","10%"),
    ]
    for name, key, weight in factor_map:
        val = sub.get(key, 0)
        bar = "█" * int(val / 5) + "░" * (20 - int(val / 5))
        lines.append(f"  {name:<18} [{bar}] {val:>3}/100  (weight {weight})")
    lines.append("")

    # ── Threat List ───────────────────────────────────────────────────────────
    if threats:
        lines += ["5.  IDENTIFIED THREATS", thin]
        for t in threats:
            lines.append(f"  • {t}")
        lines.append("")

    # ── Recommendations ───────────────────────────────────────────────────────
    lines += ["6.  REMEDIATION RECOMMENDATIONS", thin]
    for i, rec in enumerate(recs, 1):
        priority = rec.get("priority", "LOW")
        action   = rec.get("action", "")
        cmd      = rec.get("command", "")
        lines.append(f"  [{i:02d}] [{priority:<8}]  {action}")
        if cmd:
            lines.append(f"         Command: {cmd}")
    lines.append("")

    # ── Conclusion ────────────────────────────────────────────────────────────
    lines += [
        "7.  CONCLUSION",
        thin,
    ]
    if level in ("CRITICAL", "HIGH"):
        lines += [
            ("This system requires urgent attention. The vulnerabilities identified "
             "in this report are not theoretical — they have been actively exploited "
             "in the wild against real organisations. The remediation steps listed in "
             "Section 6 should be applied as soon as possible, starting with the "
             "CRITICAL-priority items."),
        ]
    else:
        lines += [
            ("The system's current security posture is acceptable but should not be "
             "treated as permanent. Cyber threats evolve continuously; regular "
             "reassessment, timely patching, and monitoring are essential to maintain "
             "a strong defence."),
        ]
    lines += [
        "",
        ("This report was generated automatically by the AI-Powered Vulnerability "
         "Assessment Engine. Results should be reviewed by a qualified security "
         "professional before acting on critical findings."),
        "",
        sep,
        f"  END OF REPORT  |  Generated: {now}",
        sep,
    ]

    return "\n".join(lines)


def save_report(text: str, path: str) -> bool:
    """Save report text to file."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return True
    except Exception as e:
        logger.error(f"save_report: {e}")
        return False
