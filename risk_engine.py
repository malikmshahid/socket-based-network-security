"""
=============================================================================
risk_engine.py - AI Risk Assessment Engine
=============================================================================
AI-Powered Intelligent Vulnerability Assessment & Threat Prediction System
Final Year Project - Computer Science

Description:
    Implements a rule-based weighted scoring algorithm that mimics AI-driven
    risk analysis. Takes raw scan results and produces:
      - Numerical risk score (0–100)
      - Risk classification (CRITICAL / HIGH / MEDIUM / LOW)
      - Threat predictions
      - Prioritised security recommendations

    ┌─────────────────────────────────────────────────┐
    │  WEIGHT DISTRIBUTION (sums to 100%)             │
    │  Open Ports        25%                          │
    │  Firewall Status   25%                          │
    │  OS Updates        20%                          │
    │  Antivirus         20%                          │
    │  Critical Ports    10%                          │
    └─────────────────────────────────────────────────┘

Author: FYP Student
Version: 1.0
=============================================================================
"""

import logging

logger = logging.getLogger(__name__)


class RiskAssessmentEngine:
    """
    AI Risk Assessment Engine.

    Uses a weighted multi-factor scoring model to quantify security risk.
    Each factor contributes a sub-score; the weighted sum forms the final
    risk score (0–100). Higher scores indicate greater vulnerability.

    Risk Levels:
        CRITICAL  → 70–100  (Immediate action required)
        HIGH      → 50–69   (Urgent remediation needed)
        MEDIUM    → 30–49   (Should be addressed soon)
        LOW       → 0–29    (Acceptable risk; monitor)
    """

    # ── Weight coefficients (must sum to 1.0) ─────────────────────────────
    WEIGHTS = {
        "open_ports":      0.25,   # 25% — number of open ports
        "firewall":        0.25,   # 25% — firewall enabled/disabled
        "os_updates":      0.20,   # 20% — pending OS updates
        "antivirus":       0.20,   # 20% — antivirus active/inactive
        "critical_ports":  0.10,   # 10% — presence of high-risk open ports
    }

    # ── Risk classification thresholds ────────────────────────────────────
    THRESHOLDS = {
        "CRITICAL": 70,
        "HIGH":     50,
        "MEDIUM":   30,
        "LOW":       0,
    }

    # ── Risk level metadata (for display purposes) ────────────────────────
    RISK_COLORS = {
        "CRITICAL": "#FF3333",   # Red
        "HIGH":     "#FF8C00",   # Orange
        "MEDIUM":   "#FFD700",   # Yellow/Gold
        "LOW":      "#32CD32",   # Green
    }

    # ── Ports considered extremely dangerous if exposed ───────────────────
    DANGEROUS_PORTS = {
        21:   "FTP (plaintext credentials, prone to brute-force)",
        22:   "SSH (brute-force target; use key-based auth)",
        23:   "Telnet (unencrypted — highly dangerous)",
        135:  "Windows RPC (WannaCry/EternalBlue vector)",
        139:  "NetBIOS (legacy protocol; exploitation target)",
        445:  "SMB (ransomware propagation vector — MS17-010)",
        3389: "Remote Desktop RDP (BlueKeep vulnerability; brute-force target)",
    }

    def __init__(self, scan_results: dict):
        """
        Initialise engine with raw scan results from VulnerabilityScanner.

        Args:
            scan_results (dict): Output from VulnerabilityScanner.run_full_scan()
        """
        self.scan_results = scan_results
        self.risk_score = 0
        self.risk_level = "LOW"
        self.sub_scores = {}         # Individual factor scores (0–100 each)
        self.weighted_scores = {}    # Sub-score × weight for each factor
        self.threats = []            # Predicted threat descriptions
        self.recommendations = []    # Actionable security advice
        logger.info("RiskAssessmentEngine initialised.")

    def analyse(self) -> dict:
        """
        Run the full risk analysis pipeline.

        Returns:
            dict: Complete assessment including score, level, threats,
                  recommendations, and per-factor breakdown.
        """
        logger.info("Starting risk analysis...")

        # ── Calculate sub-scores for each factor ──────────────────────────
        self.sub_scores["open_ports"]     = self._score_open_ports()
        self.sub_scores["firewall"]       = self._score_firewall()
        self.sub_scores["os_updates"]     = self._score_os_updates()
        self.sub_scores["antivirus"]      = self._score_antivirus()
        self.sub_scores["critical_ports"] = self._score_critical_ports()

        # ── Apply weights and sum ─────────────────────────────────────────
        total = 0.0
        for factor, raw_score in self.sub_scores.items():
            weighted = raw_score * self.WEIGHTS[factor]
            self.weighted_scores[factor] = round(weighted, 2)
            total += weighted

        self.risk_score = min(100, round(total))

        # ── Classify risk level ───────────────────────────────────────────
        self.risk_level = self._classify(self.risk_score)

        # ── Identify threats ──────────────────────────────────────────────
        self.threats = self._predict_threats()

        # ── Generate recommendations ──────────────────────────────────────
        self.recommendations = self._generate_recommendations()

        logger.info(f"Analysis complete. Score: {self.risk_score} | Level: {self.risk_level}")

        return {
            "risk_score":       self.risk_score,
            "risk_level":       self.risk_level,
            "risk_color":       self.RISK_COLORS[self.risk_level],
            "sub_scores":       self.sub_scores,
            "weighted_scores":  self.weighted_scores,
            "threats":          self.threats,
            "recommendations":  self.recommendations,
        }

    # ──────────────────────────────────────────────────────────────────────
    # SCORING FUNCTIONS  (each returns 0–100; 0 = safe, 100 = max risk)
    # ──────────────────────────────────────────────────────────────────────

    def _score_open_ports(self) -> float:
        """
        Score based on number of open ports found.
        
        Rationale: Each open port is a potential attack surface.
        Score increases non-linearly to reflect compounding exposure risk.
        """
        open_ports = self.scan_results.get("open_ports", [])
        count = len(open_ports)

        if count == 0:
            return 0
        elif count <= 2:
            return 20     # Minimal exposure
        elif count <= 5:
            return 45     # Moderate exposure
        elif count <= 8:
            return 65     # High exposure
        elif count <= 12:
            return 80     # Very high exposure
        else:
            return 100    # Maximum exposure

    def _score_firewall(self) -> float:
        """
        Score based on Windows Firewall status.
        
        Rationale: A disabled firewall exposes ALL ports and services
        to inbound network connections without filtering.
        """
        status = self.scan_results.get("firewall_status", "Unknown").upper()

        if status == "ENABLED":
            return 0      # Firewall on = no risk contribution
        elif status == "DISABLED":
            return 100    # Firewall off = maximum risk contribution
        else:
            return 50     # Unknown = assume medium risk

    def _score_os_updates(self) -> float:
        """
        Score based on OS patch/update status.
        
        Rationale: Unpatched systems are vulnerable to known CVEs
        (e.g., EternalBlue exploits unpatched SMB on Windows).
        """
        status = self.scan_results.get("os_update_status", "Unknown").upper()

        if "UP-TO-DATE" in status or "UP_TO_DATE" in status:
            return 0      # Fully patched
        elif "UPDATES AVAILABLE" in status or "UPDATES_AVAILABLE" in status:
            return 100    # Known vulnerabilities may be unpatched
        elif "RUNNING" in status:
            return 30     # Update service running but status unclear
        elif "STOPPED" in status:
            return 70     # Update service stopped — patches may be missed
        else:
            return 50     # Unknown — default to medium risk

    def _score_antivirus(self) -> float:
        """
        Score based on antivirus / Windows Defender status.
        
        Rationale: Active antivirus provides real-time threat detection
        and significantly reduces malware infection risk.
        """
        status = self.scan_results.get("antivirus_status", "Unknown").upper()

        if status == "ACTIVE":
            return 0      # Protected
        elif status == "INACTIVE":
            return 100    # No real-time protection
        else:
            return 40     # Unknown — partial risk assumed

    def _score_critical_ports(self) -> float:
        """
        Score based on whether high-risk ports are open.
        
        Rationale: Certain ports (RDP, SMB, Telnet, etc.) are primary
        targets for automated attacks and ransomware propagation.
        Each additional critical port compounds the exposure.
        """
        critical_open = self.scan_results.get("critical_ports_open", [])
        count = len(critical_open)

        if count == 0:
            return 0
        elif count == 1:
            return 40
        elif count == 2:
            return 65
        elif count == 3:
            return 80
        else:
            return 100

    # ──────────────────────────────────────────────────────────────────────
    # CLASSIFICATION
    # ──────────────────────────────────────────────────────────────────────

    def _classify(self, score: int) -> str:
        """
        Map a numerical score to a risk level string.

        Args:
            score (int): Risk score 0–100.

        Returns:
            str: "CRITICAL", "HIGH", "MEDIUM", or "LOW".
        """
        if score >= self.THRESHOLDS["CRITICAL"]:
            return "CRITICAL"
        elif score >= self.THRESHOLDS["HIGH"]:
            return "HIGH"
        elif score >= self.THRESHOLDS["MEDIUM"]:
            return "MEDIUM"
        else:
            return "LOW"

    # ──────────────────────────────────────────────────────────────────────
    # THREAT PREDICTION
    # ──────────────────────────────────────────────────────────────────────

    def _predict_threats(self) -> list:
        """
        Generate a list of predicted threat scenarios based on scan findings.

        Returns:
            list of str: Human-readable threat descriptions.
        """
        threats = []
        open_ports      = self.scan_results.get("open_ports", [])
        critical_open   = self.scan_results.get("critical_ports_open", [])
        firewall        = self.scan_results.get("firewall_status", "Unknown").upper()
        antivirus       = self.scan_results.get("antivirus_status", "Unknown").upper()
        os_update       = self.scan_results.get("os_update_status", "Unknown").upper()

        # Firewall threats
        if firewall == "DISABLED":
            threats.append(
                "⚠ FIREWALL DISABLED: System is fully exposed to inbound network attacks. "
                "Attackers can directly probe all open services."
            )

        # Antivirus threats
        if antivirus == "INACTIVE":
            threats.append(
                "⚠ NO ANTIVIRUS PROTECTION: System is vulnerable to malware, ransomware, "
                "trojans, and zero-day exploits without real-time detection."
            )

        # Critical port threats
        for port in critical_open:
            description = self.DANGEROUS_PORTS.get(port, "High-risk service")
            threats.append(f"⚠ CRITICAL PORT {port} OPEN: {description}")

        # OS update threat
        if "UPDATES AVAILABLE" in os_update or "UPDATES_AVAILABLE" in os_update:
            threats.append(
                "⚠ PENDING OS UPDATES: Known security vulnerabilities (CVEs) may be exploitable. "
                "Attackers actively scan for unpatched systems."
            )

        # Combined threats — compound risk scenarios
        if 445 in open_ports and "UPDATES AVAILABLE" in os_update:
            threats.append(
                "🔴 HIGH RISK COMBINATION: SMB port 445 open + pending updates = "
                "potential EternalBlue/WannaCry ransomware vulnerability (MS17-010)."
            )

        if 3389 in open_ports and firewall == "DISABLED":
            threats.append(
                "🔴 HIGH RISK COMBINATION: RDP port 3389 exposed + no firewall = "
                "critical remote access attack vector. BlueKeep (CVE-2019-0708) may apply."
            )

        if 23 in open_ports:
            threats.append(
                "🔴 TELNET DETECTED: Port 23 transmits credentials in plaintext. "
                "Any intercepted session reveals passwords immediately."
            )

        if 21 in open_ports:
            threats.append(
                "⚠ FTP DETECTED (Port 21): Unencrypted file transfer protocol. "
                "Susceptible to credential sniffing and man-in-the-middle attacks."
            )

        # General port exposure threat
        if len(open_ports) > 8:
            threats.append(
                f"⚠ LARGE ATTACK SURFACE: {len(open_ports)} open ports detected. "
                "Each open port is a potential entry point. Principle of Least Privilege advises "
                "closing all unnecessary services."
            )

        if not threats:
            threats.append("✅ No significant threat patterns detected based on current scan results.")

        return threats

    # ──────────────────────────────────────────────────────────────────────
    # RECOMMENDATIONS GENERATOR
    # ──────────────────────────────────────────────────────────────────────

    def _generate_recommendations(self) -> list:
        """
        Generate prioritised, actionable security recommendations.

        Returns:
            list of dict: Each dict has 'priority' and 'action' keys.
        """
        recs = []
        open_ports    = self.scan_results.get("open_ports", [])
        critical_open = self.scan_results.get("critical_ports_open", [])
        firewall      = self.scan_results.get("firewall_status", "Unknown").upper()
        antivirus     = self.scan_results.get("antivirus_status", "Unknown").upper()
        os_update     = self.scan_results.get("os_update_status", "Unknown").upper()

        # Priority 1: Firewall
        if firewall != "ENABLED":
            recs.append({
                "priority": "CRITICAL",
                "action": (
                    "Enable Windows Firewall immediately on all profiles (Domain, Private, Public). "
                    "Go to: Control Panel → Windows Defender Firewall → Turn on."
                )
            })

        # Priority 2: Antivirus
        if antivirus != "ACTIVE":
            recs.append({
                "priority": "CRITICAL",
                "action": (
                    "Enable Windows Defender or install a reputable antivirus solution. "
                    "Go to: Settings → Windows Security → Virus & Threat Protection."
                )
            })

        # Priority 3: OS Updates
        if "UPDATES AVAILABLE" in os_update or "UPDATES_AVAILABLE" in os_update:
            recs.append({
                "priority": "HIGH",
                "action": (
                    "Apply all pending Windows updates immediately. "
                    "Go to: Settings → Windows Update → Check for Updates. "
                    "Critical security patches close known CVE vulnerabilities."
                )
            })

        # Priority 4: Critical port-specific advice
        if 3389 in critical_open:
            recs.append({
                "priority": "HIGH",
                "action": (
                    "Disable Remote Desktop (RDP) if not required. "
                    "If required: restrict access by IP using firewall rules, enable NLA "
                    "(Network Level Authentication), and change the default port from 3389."
                )
            })

        if 445 in critical_open:
            recs.append({
                "priority": "HIGH",
                "action": (
                    "Restrict SMB port 445. If internal file sharing is not needed externally, "
                    "block port 445 at the firewall. Ensure MS17-010 patch is applied (KB4012212)."
                )
            })

        if 23 in critical_open:
            recs.append({
                "priority": "CRITICAL",
                "action": (
                    "DISABLE TELNET immediately (port 23). Telnet transmits all data including "
                    "passwords in plaintext. Use SSH (port 22) as a secure alternative."
                )
            })

        if 21 in critical_open:
            recs.append({
                "priority": "HIGH",
                "action": (
                    "Replace FTP (port 21) with SFTP or FTPS to encrypt file transfers. "
                    "If FTP is not required, disable the FTP server service."
                )
            })

        if 139 in critical_open or 135 in critical_open:
            recs.append({
                "priority": "HIGH",
                "action": (
                    "Ports 135 (RPC) and 139 (NetBIOS) are frequently exploited. "
                    "Block these at the perimeter firewall unless required for Active Directory."
                )
            })

        # General open ports recommendation
        if len(open_ports) > 5:
            recs.append({
                "priority": "MEDIUM",
                "action": (
                    f"{len(open_ports)} open ports detected. Apply the Principle of Least Privilege: "
                    "disable or block any service/port that is not actively required. "
                    "Use 'netstat -ano' to identify and stop unnecessary services."
                )
            })

        # Always include general best practices
        recs.append({
            "priority": "LOW",
            "action": (
                "Implement regular vulnerability scanning (weekly/monthly) to detect new risks. "
                "Consider using a SIEM solution for continuous monitoring."
            )
        })

        recs.append({
            "priority": "LOW",
            "action": (
                "Enable Windows Event Log auditing for login attempts, "
                "privilege escalation, and network connections to detect intrusion attempts."
            )
        })

        recs.append({
            "priority": "LOW",
            "action": (
                "Enforce strong password policies: minimum 12 characters, "
                "complexity requirements, and multi-factor authentication (MFA) "
                "for all administrative accounts."
            )
        })

        return recs

    def get_summary_text(self) -> str:
        """
        Return a formatted plain-text summary of the risk assessment.

        Returns:
            str: Multi-line summary suitable for display in the GUI.
        """
        lines = [
            "=" * 60,
            "  AI RISK ASSESSMENT REPORT",
            "=" * 60,
            f"  Risk Score : {self.risk_score} / 100",
            f"  Risk Level : {self.risk_level}",
            "",
            "  FACTOR BREAKDOWN:",
            f"    Open Ports Score     : {self.sub_scores.get('open_ports', 0):.0f}/100  (weight 25%)",
            f"    Firewall Score       : {self.sub_scores.get('firewall', 0):.0f}/100  (weight 25%)",
            f"    OS Updates Score     : {self.sub_scores.get('os_updates', 0):.0f}/100  (weight 20%)",
            f"    Antivirus Score      : {self.sub_scores.get('antivirus', 0):.0f}/100  (weight 20%)",
            f"    Critical Ports Score : {self.sub_scores.get('critical_ports', 0):.0f}/100  (weight 10%)",
            "",
            "  PREDICTED THREATS:",
        ]
        for t in self.threats:
            lines.append(f"    {t}")

        lines.append("")
        lines.append("  RECOMMENDATIONS:")
        for r in self.recommendations:
            lines.append(f"    [{r['priority']}] {r['action']}")

        lines.append("=" * 60)
        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────
# Quick standalone test
# ──────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mock_results = {
        "open_ports": [80, 443, 3389, 445, 22],
        "critical_ports_open": [3389, 445, 22],
        "firewall_status": "DISABLED",
        "antivirus_status": "INACTIVE",
        "os_update_status": "UPDATES AVAILABLE",
    }

    engine = RiskAssessmentEngine(mock_results)
    assessment = engine.analyse()

    print(engine.get_summary_text())
    print(f"\nRisk Score: {assessment['risk_score']} ({assessment['risk_level']})")
