================================================================================
  AI-POWERED INTELLIGENT VULNERABILITY ASSESSMENT & THREAT PREDICTION SYSTEM
  Final Year Project (FYP) — Computer Science
================================================================================

  Version   : 1.0
  Platform  : Windows 10 (Python 3.8+)
  Author    : FYP Student

================================================================================
  TABLE OF CONTENTS
================================================================================

  1.  Project Overview
  2.  Project Structure
  3.  Prerequisites
  4.  Installation Guide (Step-by-Step)
  5.  Running the Application
  6.  User Manual
  7.  How the AI Risk Scoring Works (for FYP Defence)
  8.  Troubleshooting Common Errors
  9.  Sample Output Description
  10. Requirements Summary

================================================================================
  1. PROJECT OVERVIEW
================================================================================

This system is a desktop-based vulnerability assessment tool that scans a
target host (local or remote), evaluates security weaknesses using a weighted
AI risk scoring algorithm, and generates a professional PDF report.

Core capabilities:
  - Port scanning (socket-based fallback if nmap is unavailable)
  - Windows system security checks (Firewall, Antivirus, OS Updates)
  - AI-driven risk scoring with 5 weighted factors
  - Risk classification: CRITICAL / HIGH / MEDIUM / LOW
  - Threat prediction based on vulnerability patterns
  - Security recommendations generator
  - PDF report generation via ReportLab
  - Professional dark-themed Tkinter GUI

================================================================================
  2. PROJECT STRUCTURE
================================================================================

  project/
  ├── main_app.py         Main GUI application — RUN THIS FILE
  ├── scanner.py          Vulnerability scanner module
  ├── risk_engine.py      AI risk assessment engine
  ├── report_gen.py       PDF report generator
  ├── requirements.txt    Python dependencies list
  └── README.txt          This file

================================================================================
  3. PREREQUISITES
================================================================================

  Required:
    - Windows 10 (64-bit recommended)
    - Python 3.8 or higher
      Download: https://www.python.org/downloads/

  Python Libraries (installed via pip — see Section 4):
    - reportlab      PDF generation
    - pandas         (optional, for data handling)
    - matplotlib     (optional, for future chart features)

  Built-in libraries (no installation needed):
    - tkinter        GUI framework
    - socket         Port scanning
    - subprocess     System command execution
    - platform       OS information
    - threading      Background scan threading

  Optional (for enhanced scanning):
    - python-nmap    Python binding for nmap
      Requires nmap to be installed: https://nmap.org/download.html
      NOTE: The system works WITHOUT nmap using socket-based scanning.

================================================================================
  4. INSTALLATION GUIDE (Step-by-Step for Windows 10)
================================================================================

  STEP 1: Install Python
  ──────────────────────
  a) Download Python from: https://www.python.org/downloads/
  b) During installation, CHECK "Add Python to PATH"
  c) Click "Install Now"
  d) Verify installation: open Command Prompt, type:
       python --version
     Expected output: Python 3.x.x

  STEP 2: Verify pip is installed
  ──────────────────────────────
  In Command Prompt:
    pip --version
  Expected output: pip xx.x from ...

  STEP 3: Install Required Libraries
  ────────────────────────────────────
  Open Command Prompt in the project folder (Shift + Right-click → "Open
  PowerShell/Command Prompt here"), then run:

    pip install reportlab

  Or install everything from requirements.txt:

    pip install -r requirements.txt

  STEP 4: (Optional) Install nmap for Enhanced Scanning
  ──────────────────────────────────────────────────────
  a) Download nmap installer: https://nmap.org/download.html
  b) Run the installer
  c) Then install the Python binding:
       pip install python-nmap
  d) Verify: nmap --version

  If nmap is NOT installed, the system automatically falls back to
  socket-based port scanning — all features still work.

  STEP 5: Verify All Files Are Present
  ──────────────────────────────────────
  Ensure these 4 Python files are in the SAME folder:
    - main_app.py
    - scanner.py
    - risk_engine.py
    - report_gen.py

================================================================================
  5. RUNNING THE APPLICATION
================================================================================

  Method 1: Double-click (if .py files are associated with Python)
    - Double-click main_app.py

  Method 2: Command Prompt (recommended)
    - Open Command Prompt
    - Navigate to project folder: cd C:\path\to\project
    - Run: python main_app.py

  Method 3: PowerShell
    - cd C:\path\to\project
    - python .\main_app.py

  The GUI window will open automatically.

================================================================================
  6. USER MANUAL
================================================================================

  INTERFACE OVERVIEW
  ─────────────────
  ┌──────────────────────────────────────────────────────────┐
  │           Application Title Bar                          │
  ├──────────────────────────────────────────────────────────┤
  │  [Target IP: ___________] [Start Scan] [Report] [Clear]  │
  ├──────────────────────────────────┬───────────────────────┤
  │                                  │   RISK SCORE          │
  │  Scan Output & Analysis Log      │      75               │
  │  (scrollable text area)          │   CRITICAL            │
  │                                  │                       │
  │                                  │  FACTOR SCORES:       │
  │                                  │  Open Ports: 65/100   │
  │                                  │  Firewall:   100/100  │
  │                                  │  ...                  │
  ├──────────────────────────────────┴───────────────────────┤
  │  Status Bar                                              │
  └──────────────────────────────────────────────────────────┘

  HOW TO PERFORM A SCAN
  ─────────────────────
  1. Enter target IP address in the "Target IP Address" field
       - For local machine:    127.0.0.1  (default)
       - For remote machine:   192.168.x.x  (must be reachable)

  2. Click "▶ Start Scan"
     - The scan runs in a background thread (GUI stays responsive)
     - Progress bar animates during scanning
     - Log area shows real-time updates

  3. Wait for scan to complete (typically 30–90 seconds)
     - Port scanning checks 17 common ports
     - System checks run Windows Firewall, Defender, Update queries

  4. View results in:
     - Log area: Detailed scan output + AI analysis
     - Right panel: Risk score (0–100) + risk level badge
     - Factor scores: Individual contribution of each factor

  GENERATING A PDF REPORT
  ───────────────────────
  1. After a successful scan, the "Generate PDF Report" button activates
  2. Click "📄 Generate PDF Report"
  3. Choose save location in the file dialog
  4. Click Save — report is generated in seconds
  5. Optionally open the PDF immediately when prompted

  RISK LEVEL COLOUR CODES
  ──────────────────────
  🔴 CRITICAL (70–100): Immediate action required
  🟠 HIGH     (50–69):  Urgent remediation needed
  🟡 MEDIUM   (30–49):  Should be addressed soon
  🟢 LOW      (0–29):   Acceptable risk; continue monitoring

================================================================================
  7. HOW THE AI RISK SCORING WORKS (for FYP Defence Presentation)
================================================================================

  The system uses a Rule-Based Weighted Multi-Factor Scoring Algorithm,
  a well-established technique in expert systems and risk analysis that
  forms the foundation of many commercial vulnerability scanners.

  ALGORITHM OVERVIEW
  ──────────────────
  Five security factors are evaluated independently. Each factor produces
  a sub-score from 0 to 100 (0 = safe, 100 = maximum risk). The sub-scores
  are then multiplied by their respective weights and summed to produce the
  final risk score.

  FORMULA:
    Risk Score = Σ (Factor_Score × Factor_Weight)

  Where:
    Factor_Score  ∈ [0, 100]
    Factor_Weight values sum to 1.0 (100%)

  FACTOR WEIGHTS & RATIONALE
  ──────────────────────────

  ┌──────────────────────┬────────┬─────────────────────────────────────────┐
  │ Factor               │ Weight │ Rationale                               │
  ├──────────────────────┼────────┼─────────────────────────────────────────┤
  │ Open Ports           │  25%  │ Each open port = potential attack vector │
  │ Firewall Status      │  25%  │ Disabled firewall = unrestricted access  │
  │ OS Update Status     │  20%  │ Unpatched = known CVEs exploitable       │
  │ Antivirus Status     │  20%  │ No AV = malware executes undetected      │
  │ Critical Ports Open  │  10%  │ Specific high-risk services (RDP, SMB)  │
  └──────────────────────┴────────┴─────────────────────────────────────────┘

  FACTOR SCORING DETAIL
  ─────────────────────

  1. Open Ports Score (0–100):
       0 ports  → 0    (no exposure)
       1-2      → 20   (minimal)
       3-5      → 45   (moderate)
       6-8      → 65   (high)
       9-12     → 80   (very high)
       12+      → 100  (maximum)

  2. Firewall Score:
       ENABLED  → 0    (protected)
       DISABLED → 100  (maximum risk)
       Unknown  → 50   (conservative estimate)

  3. OS Updates Score:
       UP-TO-DATE        → 0
       UPDATES AVAILABLE → 100
       Service Running   → 30
       Service Stopped   → 70

  4. Antivirus Score:
       ACTIVE   → 0
       INACTIVE → 100
       Unknown  → 40

  5. Critical Ports Score (ports: 21, 22, 23, 135, 139, 445, 3389):
       0 critical ports → 0
       1                → 40
       2                → 65
       3                → 80
       4+               → 100

  WORKED EXAMPLE:
  ───────────────
  Scenario: 5 open ports, Firewall disabled, updates pending,
            Antivirus active, 2 critical ports open.

    Open Ports     : 45 × 0.25 = 11.25
    Firewall       : 100 × 0.25 = 25.00
    OS Updates     : 100 × 0.20 = 20.00
    Antivirus      : 0   × 0.20 =  0.00
    Critical Ports : 65  × 0.10 =  6.50
                                  ──────
    Total Risk Score             = 62.75 → Rounded to 63 → HIGH

  THREAT PREDICTION LOGIC:
  ─────────────────────────
  The engine applies pattern matching to detect compound vulnerabilities:
    - SMB (445) open + pending updates → EternalBlue/WannaCry risk
    - RDP (3389) open + firewall off   → BlueKeep exploitation risk
    - Telnet (23) open                 → Plaintext credential exposure
    - No antivirus                     → Malware execution risk

  WHY THIS APPROACH?
  ──────────────────
  1. Transparent: Each factor's contribution is quantifiable and explainable
  2. Configurable: Weights can be tuned based on organisational policy
  3. Extensible: New factors (e.g., patch age, user account auditing) can be
     added without redesigning the algorithm
  4. Industry-standard: Used in frameworks like CVSS (Common Vulnerability
     Scoring System) and NIST risk assessment guidelines

================================================================================
  8. TROUBLESHOOTING COMMON ERRORS
================================================================================

  ERROR: "ModuleNotFoundError: No module named 'reportlab'"
  ─────────────────────────────────────────────────────────
  Solution: pip install reportlab

  ERROR: "ModuleNotFoundError: No module named 'scanner'"
  ─────────────────────────────────────────────────────────
  Solution: Ensure all 4 Python files are in the SAME directory.
            Run python main_app.py from that directory.

  ERROR: "No module named tkinter"
  ─────────────────────────────────
  Solution: Reinstall Python. On Windows, Tkinter is bundled by default.
            Ensure you downloaded the official installer from python.org.

  ERROR: Access Denied during firewall/antivirus checks
  ──────────────────────────────────────────────────────
  Solution: Run Command Prompt as Administrator before launching the app.
            Right-click Command Prompt → "Run as Administrator"
            Then: python main_app.py

  ERROR: Scan hangs or takes very long
  ─────────────────────────────────────
  Cause: Network timeout on unreachable remote IP
  Solution: Use 127.0.0.1 for local scans. For remote IPs, ensure the
            target is reachable (ping the IP first).

  ERROR: PDF report fails to open / not found
  ────────────────────────────────────────────
  Solution: Check the save path chosen in the dialog. Avoid paths with
            special characters. Try saving to Desktop or C:\Reports\.

  WARNING: "python-nmap not found. Using socket-based fallback scanner."
  ───────────────────────────────────────────────────────────────────────
  This is NOT an error. The system works fine using socket scanning.
  To enable nmap: pip install python-nmap (also install nmap from nmap.org)

  ERROR: PowerShell execution policy
  ────────────────────────────────────
  If Get-MpComputerStatus fails, run this in PowerShell as Admin:
    Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
  Then rerun the application.

  Antivirus shows "Unknown" on non-Windows systems
  ─────────────────────────────────────────────────
  The antivirus check uses Windows-specific commands.
  On non-Windows, this will return "Unknown" — this is expected behaviour.

================================================================================
  9. SAMPLE OUTPUT DESCRIPTION
================================================================================

  When scanning localhost (127.0.0.1), a typical output looks like:

  ═══════════════════════════════════════════════════════
    STARTING VULNERABILITY SCAN
    Target   : 127.0.0.1
    Started  : 2024-01-15 14:30:22
  ═══════════════════════════════════════════════════════
  [*] Gathering system information...
      Hostname : DESKTOP-XYZ
      OS       : Windows
      Local IP : 192.168.1.105

  [*] Starting port scan on 127.0.0.1...
      nmap not found — using socket-based scanner...
      Scanning port 21 (FTP)... [1/17]
      Scanning port 22 (SSH)... [2/17]
      ...
      → Port 80 OPEN  [HTTP]
      → Port 443 OPEN [HTTPS]
      Open ports found   : 2
      Critical ports open: 0

  [*] Checking Windows Firewall status...
      Firewall: ENABLED

  [*] Checking Antivirus / Windows Defender status...
      Antivirus: ACTIVE

  [*] Checking OS update status...
      OS Updates: UP-TO-DATE

  [✓] Scan complete.

  ═══════════════════════════════════════════════════════
    AI RISK ASSESSMENT RESULTS
  ═══════════════════════════════════════════════════════
    Risk Score : 10 / 100
    Risk Level : LOW

    FACTOR BREAKDOWN:
      Open Ports     : 20/100  (wt 25%)
      Firewall       : 0/100   (wt 25%)
      OS Updates     : 0/100   (wt 20%)
      Antivirus      : 0/100   (wt 20%)
      Critical Ports : 0/100   (wt 10%)

    PREDICTED THREATS:
      ✅ No significant threat patterns detected.

    RECOMMENDATIONS:
      [LOW] Implement regular vulnerability scanning...
      [LOW] Enable Windows Event Log auditing...

  ═══════════════════════════════════════════════════════

  PDF REPORT CONTENTS:
  ─────────────────────
  Page 1:
    - Header banner (dark blue, system title)
    - Scan metadata table (hostname, IP, timestamp, OS)
    - Risk summary: large colour-coded score badge + legend bar

  Page 2:
    - Factor breakdown table (sub-scores, weights, weighted scores)
    - Open ports table (port, service, status, risk level)
    - Predicted threats list

  Page 3:
    - Security recommendations table (colour-coded by priority)
    - Footer with project attribution

================================================================================
  10. REQUIREMENTS SUMMARY (requirements.txt)
================================================================================

  See requirements.txt file for the pip-installable dependency list.
  Core: reportlab
  Optional: python-nmap, matplotlib, pandas

================================================================================
  END OF README
================================================================================
