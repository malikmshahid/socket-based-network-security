"""
=============================================================================
main_app.py - COMPLETE SECURITY SUITE v5.0
=============================================================================
AI-Powered Intelligent Vulnerability Assessment & Threat Prediction System
Final Year Project - Computer Science

ALL FEATURES:
  ✓ Splash Screen + Login (admin/admin123)
  ✓ Urdu/English Language Toggle
  ✓ Vulnerability Scanner + AI Risk Engine
  ✓ Network Map - connected devices
  ✓ System Performance Monitor (CPU/RAM/Disk/Net)
  ✓ Password Strength Checker
  ✓ Security Awareness Lab (attacks, CMD, CVEs)
  ✓ Scan History (auto-saved)
  ✓ Firewall Rules Manager (GUI)
  ✓ Auto-Fix Engine (one-click fixes)
  ✓ Real-Time Alert System (popup threats)
  ✓ Scheduled Auto-Scan (daily/weekly)
  ✓ System Hardening Checklist
  ✓ Threat World Map (visual)
  ✓ Dark/Light Theme Toggle
  ✓ PDF Export + Email Report
=============================================================================
"""

import tkinter as tk
import queue as _queue
from tkinter import ttk, messagebox, filedialog
import threading, os, socket, logging, subprocess, hashlib, string, secrets
import calendar
from datetime import datetime

# Core modules
from scanner      import VulnerabilityScanner
from risk_engine  import RiskAssessmentEngine
from report_gen   import ReportGenerator
from network_map  import NetworkMapper
from sys_monitor  import SystemMonitor
from scan_history import ScanHistory
from firewall_manager import FirewallManager
from auto_fix     import AutoFixer
from alert_system import AlertSystem
from scheduler    import ScanScheduler
from wifi_scanner    import full_wifi_scan
from malware_scanner import MalwareScanner
from usb_monitor     import USBMonitor
from breach_checker  import check_email, check_password_pwned, get_latest_breaches
from report_card     import generate_report_card
from ctf_challenges      import get_all_challenges, check_answer, get_total_points
from otp_auth            import generate_totp, verify_totp, generate_secret, save_otp_config, load_otp_config, get_qr_uri
from speed_test          import SpeedTester
from score_history_graph import load_graph_data, add_scan_point, get_stats, draw_graph
import score_history_graph
from process_monitor     import get_processes, kill_process, get_suspicious_processes
from ip_geolocator       import lookup_ip, get_my_ip
from password_manager    import PasswordManager

from vuln_timeline       import draw_calendar, get_calendar_data, get_all_months, get_day_color
from traffic_graph       import TrafficMonitor, draw_traffic_graph
from darkweb_monitor     import DarkWebMonitor
from exploit_db          import search_nvd_api, get_latest_cves, SEVERITY_COLORS as CVE_COLORS, OFFLINE_DB
from backup_restore      import (create_backup, list_backups, restore_backup,
                                  delete_backup, get_backup_stats,
                                  save_app_settings, load_app_settings)
from attack_simulator    import AttackSimulator, SIMULATIONS
from wifi_advanced       import (analyze_pw_strength, wifi_qr_string,
                                draw_qr_on_canvas, export_wifi_csv, export_wifi_html)
from ai_chat             import get_ai_response
from pentest_tools       import (
    nmap_available, run_nmap, NMAP_PRESETS,
    get_defender_status, run_defender_scan, update_defender_signatures, get_defender_threats,
    detect_steganography, scan_folder_stego,
    encrypt_message, decrypt_message, load_chat_messages, save_chat_message,
    get_live_connections, capture_dns_queries, get_bandwidth_per_process,
    crack_hash, identify_hash_type, HASH_ALGOS, BUILTIN_WORDLIST,
    PHISHING_TEMPLATES, PRETEXTING_SCRIPTS, generate_phishing_report,
    MSF_MODULES, MSF_COMMANDS, generate_msf_command, check_msf_installed,
    get_system_analytics, calculate_security_score,
)
from security_tools      import (
    get_wifi_passwords, check_vpn_status, analyze_url,
    scan_ransomware_indicators, detect_rogue_ap,
    scan_keylogger_indicators, detect_port_knocking,
    get_disk_usage, get_top_connections, get_battery_info,
    get_uptime, get_login_attempts,
    calculate_hashes, b64_encode, b64_decode, subnet_calc,
)
from security_news       import fetch_news

logging.basicConfig(level=logging.INFO)

# ══════════════════════════════════════════════════════════════════════════
# LANGUAGE STRINGS (Urdu/English)
# ══════════════════════════════════════════════════════════════════════════

LANG = {
    "en": {
        "app_title":      "AI-POWERED VULNERABILITY ASSESSMENT SYSTEM",
        "subtitle":       "THREAT PREDICTION  ▸  NETWORK MAP  ▸  SYSTEM MONITOR  ▸  v11.0",
        "tab_scanner":    "  ◈ SCANNER  ",
        "tab_network":    "  ◈ NETWORK MAP  ",
        "tab_monitor":    "  ◈ SYS MONITOR  ",
        "tab_password":   "  ◈ PASSWORD CHECK  ",
        "tab_firewall":   "  ◈ FIREWALL MGR  ",
        "tab_autofix":    "  ◈ AUTO-FIX  ",
        "tab_alerts":     "  ◈ ALERTS  ",
        "tab_schedule":   "  ◈ SCHEDULER  ",
        "tab_hardening":  "  ◈ HARDENING  ",
        "tab_threatmap":  "  ◈ THREAT MAP  ",
        "tab_seclab":     "  ◈ SECURITY LAB  ",
        "tab_history":    "  ◈ HISTORY  ",
        "btn_scan":       "▶  INITIATE SCAN",
        "btn_scanning":   "◉  SCANNING...",
        "btn_pdf":        "⬇  EXPORT PDF",
        "btn_email":      "✉  EMAIL",
        "btn_clear":      "✕ CLEAR",
        "btn_detect":     "⟳ DETECT",
        "target_ip":      "TARGET IP",
        "threat_level":   "THREAT LEVEL",
        "system_info":    "SYSTEM INFO",
        "sec_status":     "SECURITY STATUS",
        "risk_factors":   "RISK FACTOR ANALYSIS",
        "ready":          "SYSTEM READY",
        "scan_complete":  "SCAN COMPLETE",
        "lang_toggle":    "🌐 اردو",
        "theme_dark":     "🌙 DARK",
        "theme_light":    "☀ LIGHT",
        "welcome":        "Welcome",
        "no_scan":        "NO SCAN",
        "tab_timeline":   "  ◈ TIMELINE  ",
        "tab_traffic":    "  ◈ TRAFFIC  ",
        "tab_dashboard":  "  ◈ DASHBOARD  ",
        "tab_darkweb":    "  ◈ DARK WEB  ",
        "tab_cve":        "  ◈ CVE SEARCH  ",
        "tab_backup":     "  ◈ BACKUP  ",
        "dashboard_sys":  "SYSTEM DASHBOARD",
        "dashboard_net":  "NETWORK DASHBOARD",
        "scan_now":       "SCAN NOW",
        "refresh":        "REFRESH",
        "export":         "EXPORT",
        "loading":        "Loading...",
        "no_data":        "No data available",
    },
    "ur": {
        "app_title":      "اے آئی پاورڈ وَلنریبلٹی اسیسمنٹ سسٹم",
        "subtitle":       "خطرہ پیشگوئی  ▸  نیٹ ورک میپ  ▸  سسٹم مانیٹر  ▸  v11.0",
        "tab_scanner":    "  ◈ اسکینر  ",
        "tab_network":    "  ◈ نیٹ ورک میپ  ",
        "tab_monitor":    "  ◈ سسٹم مانیٹر  ",
        "tab_password":   "  ◈ پاس ورڈ چیک  ",
        "tab_firewall":   "  ◈ فائر وال  ",
        "tab_autofix":    "  ◈ آٹو فکس  ",
        "tab_alerts":     "  ◈ الرٹس  ",
        "tab_schedule":   "  ◈ شیڈیولر  ",
        "tab_hardening":  "  ◈ سیکیورٹی مضبوطی  ",
        "tab_threatmap":  "  ◈ خطرہ نقشہ  ",
        "tab_seclab":     "  ◈ سیکیورٹی لیب  ",
        "tab_history":    "  ◈ تاریخ  ",
        "btn_scan":       "▶  اسکین شروع کریں",
        "btn_scanning":   "◉  اسکیننگ...",
        "btn_pdf":        "⬇  پی ڈی ایف",
        "btn_email":      "✉  ای میل",
        "btn_clear":      "✕ صاف کریں",
        "btn_detect":     "⟳ ڈیٹیکٹ",
        "target_ip":      "ہدف آئی پی",
        "threat_level":   "خطرہ کی سطح",
        "system_info":    "سسٹم معلومات",
        "sec_status":     "سیکیورٹی حالت",
        "risk_factors":   "خطرے کے عوامل",
        "ready":          "سسٹم تیار ہے",
        "scan_complete":  "اسکین مکمل",
        "lang_toggle":    "🌐 English",
        "theme_dark":     "🌙 ڈارک",
        "theme_light":    "☀ لائٹ",
        "welcome":        "خوش آمدید",
        "no_scan":        "کوئی اسکین نہیں",
        "tab_timeline":   "  ◈ ٹائم لائن  ",
        "tab_traffic":    "  ◈ ٹریفک  ",
        "tab_dashboard":  "  ◈ ڈیش بورڈ  ",
        "tab_darkweb":    "  ◈ ڈارک ویب  ",
        "tab_cve":        "  ◈ سی وی ای  ",
        "tab_backup":     "  ◈ بیک اپ  ",
        "dashboard_sys":  "سسٹم ڈیش بورڈ",
        "dashboard_net":  "نیٹ ورک ڈیش بورڈ",
        "scan_now":       "ابھی اسکین کریں",
        "refresh":        "تازہ کریں",
        "export":         "برآمد کریں",
        "loading":        "لوڈ ہو رہا ہے...",
        "no_data":        "کوئی ڈیٹا نہیں",
    },
}

# ══════════════════════════════════════════════════════════════════════════
# THEMES — Day / Night / Dark / Light / Purple / Matrix / Ocean
# ══════════════════════════════════════════════════════════════════════════
THEMES = {
    "dark": {
        "BG_DEEP":"#050A0F","BG_PANEL":"#0A1628","BG_CARD":"#0D1F35",
        "BG_ELEVATED":"#112240","CYAN":"#00D4FF","CYAN_DIM":"#007A94",
        "GREEN":"#00FF88","GREEN_DIM":"#00994D","RED":"#FF2D55",
        "ORANGE":"#FF8C42","YELLOW":"#FFD60A","TEXT_BRIGHT":"#E8F4FD",
        "TEXT_MID":"#7BAFD4","TEXT_DIM":"#3A6080","LOG_BG":"#020609",
    },
    "light": {
        "BG_DEEP":"#F0F4F8","BG_PANEL":"#FFFFFF","BG_CARD":"#F7FAFC",
        "BG_ELEVATED":"#EDF2F7","CYAN":"#0066CC","CYAN_DIM":"#3388DD",
        "GREEN":"#00875A","GREEN_DIM":"#36B37E","RED":"#DE350B",
        "ORANGE":"#FF8B00","YELLOW":"#FF991F","TEXT_BRIGHT":"#172B4D",
        "TEXT_MID":"#344563","TEXT_DIM":"#6B778C","LOG_BG":"#FAFAFA",
    },
    "day": {
        "BG_DEEP":"#F8FAFC","BG_PANEL":"#FFFFFF","BG_CARD":"#F1F5F9",
        "BG_ELEVATED":"#E2E8F0","CYAN":"#2563EB","CYAN_DIM":"#93C5FD",
        "GREEN":"#16A34A","GREEN_DIM":"#86EFAC","RED":"#DC2626",
        "ORANGE":"#EA580C","YELLOW":"#D97706","TEXT_BRIGHT":"#0F172A",
        "TEXT_MID":"#1E40AF","TEXT_DIM":"#64748B","LOG_BG":"#F8FAFC",
    },
    "night": {
        "BG_DEEP":"#000000","BG_PANEL":"#0D0D0D","BG_CARD":"#141414",
        "BG_ELEVATED":"#1C1C1C","CYAN":"#60A5FA","CYAN_DIM":"#1D4ED8",
        "GREEN":"#4ADE80","GREEN_DIM":"#166534","RED":"#F87171",
        "ORANGE":"#FB923C","YELLOW":"#FBBF24","TEXT_BRIGHT":"#F9FAFB",
        "TEXT_MID":"#9CA3AF","TEXT_DIM":"#374151","LOG_BG":"#050505",
    },
    "purple": {
        "BG_DEEP":"#0A0514","BG_PANEL":"#130A24","BG_CARD":"#1A0F33",
        "BG_ELEVATED":"#221445","CYAN":"#BB86FC","CYAN_DIM":"#6A3A9A",
        "GREEN":"#03DAC6","GREEN_DIM":"#018786","RED":"#CF6679",
        "ORANGE":"#FFAB40","YELLOW":"#FFD740","TEXT_BRIGHT":"#F0E6FF",
        "TEXT_MID":"#9E7BC4","TEXT_DIM":"#4A2D6A","LOG_BG":"#060210",
    },
    "matrix": {
        "BG_DEEP":"#000000","BG_PANEL":"#001100","BG_CARD":"#001A00",
        "BG_ELEVATED":"#002200","CYAN":"#00FF41","CYAN_DIM":"#007A1F",
        "GREEN":"#00FF41","GREEN_DIM":"#007A1F","RED":"#FF0033",
        "ORANGE":"#FFAA00","YELLOW":"#FFFF00","TEXT_BRIGHT":"#CCFFCC",
        "TEXT_MID":"#00BB30","TEXT_DIM":"#004410","LOG_BG":"#000500",
    },
    "ocean": {
        "BG_DEEP":"#020B18","BG_PANEL":"#051525","BG_CARD":"#081E33",
        "BG_ELEVATED":"#0A2744","CYAN":"#00E5FF","CYAN_DIM":"#0077AA",
        "GREEN":"#69FF47","GREEN_DIM":"#2E7D32","RED":"#FF5252",
        "ORANGE":"#FFD740","YELLOW":"#FFFF00","TEXT_BRIGHT":"#E3F2FD",
        "TEXT_MID":"#64B5F6","TEXT_DIM":"#1A4A6A","LOG_BG":"#010810",
    },
}

T = THEMES["dark"]

# ── App Config ────────────────────────────────────────────────────────────
APP_CONFIG = {
    "custom_titlebar": True,   # Set False if app crashes on startup
    "startup_delay":   400,    # ms before background services start
}

RISK_COLORS = {"CRITICAL":"#FF2D55","HIGH":"#FF8C42","MEDIUM":"#FFD60A","LOW":"#00FF88"}

def detect_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close(); return ip
    except:
        try: return socket.gethostbyname(socket.gethostname())
        except: return "127.0.0.1"

def _run_cmd(cmd):
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=10, creationflags=flags)
        return r.returncode==0, r.stdout+r.stderr
    except Exception as e:
        return False, str(e)

# ══════════════════════════════════════════════════════════════════════════
# CANVAS WIDGETS
# ══════════════════════════════════════════════════════════════════════════

class RiskMeter(tk.Canvas):
    def __init__(self, parent, size=180, **kwargs):
        bg = kwargs.pop("bg", T["BG_PANEL"])
        super().__init__(parent, width=size, height=size,
                         bg=bg, highlightthickness=0, **kwargs)
        self.size=size; self.score=0; self.target=0; self.level="LOW"
        self._draw_base()
    def _draw_base(self):
        self.delete("all"); cx=cy=self.size//2; r=cx-10
        self.create_arc(cx-r,cy-r,cx+r,cy+r,start=-210,extent=240,
                        style=tk.ARC,outline=T["TEXT_DIM"],width=3)
        self._st=self.create_text(cx,cy-8,text="--",font=("Consolas",28,"bold"),fill=T["TEXT_DIM"])
        self._lt=self.create_text(cx,cy+22,text="NO SCAN",font=("Segoe UI",8,"bold"),fill=T["TEXT_DIM"])
        self._arc=None
    def animate_to(self,target,level):
        self.target=target; self.level=level; self._step()
    def _step(self):
        if self.score<self.target:
            self.score=min(self.score+2,self.target); self._redraw(); self.after(18,self._step)
        else: self.score=self.target; self._redraw()
    def _redraw(self):
        cx=cy=self.size//2; r=cx-10
        color=RISK_COLORS.get(self.level,T["CYAN"])
        if self._arc: self.delete(self._arc)
        ext=int(240*self.score/100)
        if ext>0:
            self._arc=self.create_arc(cx-r,cy-r,cx+r,cy+r,
                start=210-ext,extent=ext,style=tk.ARC,outline=color,width=8)
        self.itemconfig(self._st,text=str(self.score),fill=color)
        self.itemconfig(self._lt,text=self.level,fill=color)
    def reset(self):
        self.score=0; self.target=0; self._draw_base()

class MiniBar(tk.Canvas):
    def __init__(self,parent,width=200,height=12,color=None,**kwargs):
        bg=kwargs.pop("bg",T["BG_CARD"])
        super().__init__(parent,width=width,height=height,
                         bg=bg,highlightthickness=0,**kwargs)
        self.w=width; self.h=height; self.color=color or T["CYAN"]
        self.create_rectangle(0,2,width,height-2,fill=T["BG_ELEVATED"],outline="")
        self._bar=self.create_rectangle(0,2,0,height-2,fill=self.color,outline="")
    def set_value(self,pct,color=None):
        if color: self.color=color
        w=int(self.w*min(pct,100)/100)
        self.itemconfig(self._bar,fill=self.color)
        self.coords(self._bar,0,2,w,self.h-2)
    def animate_to(self,pct,color=None):
        if color: self.color=color
        target=int(self.w*min(pct,100)/100)
        cur=self.coords(self._bar)[2] if self.coords(self._bar) else 0
        self._anim(cur,target)
    def _anim(self,cur,target):
        if cur<target:
            cur=min(cur+4,target)
            self.coords(self._bar,0,2,cur,self.h-2)
            self.itemconfig(self._bar,fill=self.color)
            self.after(12,lambda:self._anim(cur,target))
        else: self.coords(self._bar,0,2,target,self.h-2)

# ══════════════════════════════════════════════════════════════════════════
# PASSWORD CHECKER
# ══════════════════════════════════════════════════════════════════════════

def check_password(pw):
    score=0; checks={}
    checks["length_8"]=len(pw)>=8; score+=10 if checks["length_8"] else 0
    checks["length_12"]=len(pw)>=12; score+=15 if checks["length_12"] else 0
    checks["upper"]=any(c.isupper() for c in pw); score+=15 if checks["upper"] else 0
    checks["lower"]=any(c.islower() for c in pw); score+=10 if checks["lower"] else 0
    checks["digit"]=any(c.isdigit() for c in pw); score+=15 if checks["digit"] else 0
    checks["special"]=any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in pw); score+=20 if checks["special"] else 0
    common=["password","123456","qwerty","admin","letmein","welcome","monkey","abc123","Shahid123"]
    checks["no_common"]=pw.lower() not in common
    if not checks["no_common"]: score=max(0,score-40)
    else: score+=15
    if score>=80: lvl,col="STRONG","#00FF88"
    elif score>=60: lvl,col="GOOD","#00D4FF"
    elif score>=40: lvl,col="MODERATE","#FFD60A"
    elif score>=20: lvl,col="WEAK","#FF8C42"
    else: lvl,col="VERY WEAK","#FF2D55"
    crack=("Centuries" if score>=80 else "Years" if score>=60 else
           "Days-Months" if score>=40 else "Hours" if score>=20 else "Seconds")
    suggs=[]
    if not checks["length_12"]: suggs.append("Use 12+ characters")
    if not checks["upper"]: suggs.append("Add uppercase letters (A-Z)")
    if not checks["digit"]: suggs.append("Add numbers (0-9)")
    if not checks["special"]: suggs.append("Add special characters (!@#$)")
    if not checks["no_common"]: suggs.append("⚠ THIS IS A COMMON PASSWORD — change immediately!")
    return {"score":score,"level":lvl,"color":col,"checks":checks,"crack":crack,"suggestions":suggs}

# ══════════════════════════════════════════════════════════════════════════
# SECURITY LAB DATA
# ══════════════════════════════════════════════════════════════════════════

ATTACKS=[
    {"title":"🔍 PORT SCANNING","color":"#0099CC",
     "diagram":"  ATTACKER──[probe ports]──▶TARGET\n  Port 80? OPEN✓  Port 3389? OPEN✓  Port 445? OPEN✓\n  Attacker maps complete attack surface",
     "what":"Automated tools probe every port to find open services.","risk":"Every open port = potential entry point.",
     "protect":["netstat -ano","netsh advfirewall set allprofiles state on"]},
    {"title":"💥 BRUTE FORCE","color":"#CC2200",
     "diagram":"  TOOL──[try 10,000 passwords/sec]──▶LOGIN\n  admin:123456✗  admin:password✗ ... admin:P@ss✓ ACCESS!",
     "what":"Software tries thousands of passwords automatically.","risk":"Weak passwords crack in seconds.",
     "protect":["net accounts /lockoutthreshold:5","net accounts /minpwlen:12"]},
    {"title":"🦠 RANSOMWARE","color":"#7700CC",
     "diagram":"  EMAIL──[malicious attachment]──▶YOUR PC\n  [Silent install]──▶[Encrypt ALL files]──▶💰RANSOM\n  WannaCry 2017: 200,000 infected, $4B damage",
     "what":"Encrypts all files, demands Bitcoin ransom.","risk":"SMB 445 open + unpatched Windows = WannaCry risk.",
     "protect":["sc query WinDefend","netsh advfirewall firewall add rule name=BlockSMB protocol=TCP dir=in localport=445 action=block"]},
    {"title":"🕵️ MAN-IN-THE-MIDDLE","color":"#CC6600",
     "diagram":"  YOUR PC──DATA──▶HACKER──▶SERVER\n  Hacker reads/modifies everything\n  Public WiFi = danger zone",
     "what":"Hacker intercepts all traffic between you and server.","risk":"Passwords, bank details all visible.",
     "protect":["ipconfig /flushdns","netsh wlan show profiles"]},
]

HARDENING_CHECKLIST = [
    ("CRITICAL","Enable Windows Firewall","netsh advfirewall set allprofiles state on",
     "Firewall blocks unauthorized network access"),
    ("CRITICAL","Block RDP Port 3389","netsh advfirewall firewall add rule name=BlockRDP protocol=TCP dir=in localport=3389 action=block",
     "Prevents BlueKeep and brute force RDP attacks"),
    ("CRITICAL","Block SMB Port 445","netsh advfirewall firewall add rule name=BlockSMB protocol=TCP dir=in localport=445 action=block",
     "Prevents WannaCry/EternalBlue ransomware"),
    ("HIGH","Enable Account Lockout","net accounts /lockoutthreshold:5 /lockoutduration:30",
     "Locks account after 5 wrong passwords"),
    ("HIGH","Set Minimum Password Length","net accounts /minpwlen:12",
     "Enforces strong passwords system-wide"),
    ("HIGH","Disable Telnet Port 23","netsh advfirewall firewall add rule name=BlockTelnet protocol=TCP dir=in localport=23 action=block",
     "Telnet sends credentials in plaintext"),
    ("HIGH","Check Windows Defender","sc query WinDefend",
     "Verify antivirus is running"),
    ("MEDIUM","Run Windows Update","wuauclt /detectnow",
     "Install latest security patches"),
    ("MEDIUM","Flush DNS Cache","ipconfig /flushdns",
     "Remove potential DNS poisoning"),
    ("MEDIUM","Disable Print Spooler","sc stop Spooler && sc config Spooler start=disabled",
     "Fixes PrintNightmare CVE-2021-34527"),
    ("LOW","Review User Accounts","net user",
     "Check for unauthorized user accounts"),
    ("LOW","Check Installed Patches","wmic qfe list | findstr KB4012212",
     "Verify critical patches are installed"),
]

THREAT_LOCATIONS = [
    (55.75, 37.62, "Moscow, Russia", "APT29, Fancy Bear", "#FF2D55"),
    (39.92, 116.39, "Beijing, China", "APT1, APT10, Lazarus", "#FF2D55"),
    (37.57, 126.98, "Pyongyang, N.Korea", "Lazarus Group", "#FF8C42"),
    (35.69, 51.39, "Tehran, Iran", "APT33, Charming Kitten", "#FF8C42"),
    (38.90,-77.04, "Washington DC, USA", "NSA (defensive)", "#FFD60A"),
    (51.51, -0.13, "London, UK", "GCHQ (defensive)", "#FFD60A"),
    (48.86,  2.35, "Paris, France", "Cybercrime groups", "#FF8C42"),
    (52.52, 13.41, "Berlin, Germany", "Financial fraud groups", "#FFD60A"),
    (1.35,  103.82, "Singapore", "APAC threat actors", "#FF8C42"),
    (28.61, 77.21, "New Delhi, India", "Various APTs", "#FFD60A"),
    (-23.55,-46.63, "São Paulo, Brazil", "Banking trojans", "#FF8C42"),
    (6.45,   3.40, "Lagos, Nigeria", "BEC fraud groups", "#FF8C42"),
]

# ══════════════════════════════════════════════════════════════════════════
# MAIN APP
# ══════════════════════════════════════════════════════════════════════════

class App(tk.Tk):
    def __init__(self, logged_in_user="Shahid"):
        super().__init__()
        self.logged_in_user = logged_in_user
        self.current_theme  = "dark"
        self.current_lang   = "en"
        self.L = LANG["en"]

        self._win_maximized = False
        self._drag_x = 0; self._drag_y = 0

        self.title("CyberShield Pro v11.0 — AI Vulnerability Assessment")
        self.geometry("1350x900")
        self.minsize(1150,760)
        # Custom titlebar — remove Windows chrome (AFTER geometry)
        # Custom titlebar — only if enabled in config
        if APP_CONFIG.get("custom_titlebar", True):
            try:
                self.overrideredirect(True)
            except Exception:
                pass
        self.configure(bg=T["BG_DEEP"])

        # Threat score live
        self._threat_score = 0
        self._threat_level  = "SAFE"
        # Password generator
        self._pw_gen_length = 20
        # WiFi pw data store
        self._wifi_pw_data  = []
        # AI Chat history
        self._chat_history  = []
        # Tray icon
        self._tray_icon     = None
        self._tray_running  = False

        self.scan_results = None; self.risk_result = None
        # Pre-initialize widget vars to prevent AttributeError
        self.graph_stats_var  = tk.StringVar(value="No scan data")
        self._dash_traffic_data = {}
        self._ui_queue = _queue.Queue()  # thread-safe UI update queue
        self._mainloop_ready = threading.Event()  # set when mainloop starts
        self.scan_running = False; self.net_scanning = False

        # Modules
        # Initialize all modules safely
        self._ctf_solved  = set()
        self._ctf_score   = 0
        self._font_size   = 10
        self._pm_unlocked = False

        def _safe_init(fn, fallback=None):
            try: return fn()
            except Exception: return fallback

        self.scan_history = _safe_init(ScanHistory)
        self.fw_manager   = _safe_init(FirewallManager)
        self.auto_fixer   = _safe_init(AutoFixer)
        self.mal_scanner  = _safe_init(MalwareScanner)
        self._pm          = _safe_init(PasswordManager)
        self.sys_monitor  = _safe_init(lambda: SystemMonitor(interval=1.5))
        self.alert_system = _safe_init(lambda: AlertSystem(alert_callback=self._on_alert))
        self.scheduler    = _safe_init(lambda: ScanScheduler(scan_callback=self._scheduled_scan))
        self.usb_monitor  = _safe_init(lambda: USBMonitor(alert_callback=self._on_usb_event))
        self.attack_sim   = _safe_init(lambda: AttackSimulator(output_callback=self._on_sim_output))
        # Traffic & DarkWeb — callback set after _build_ui to avoid tkapp issues
        self._traffic_mon = _safe_init(lambda: TrafficMonitor(update_callback=None))
        self._dw_monitor  = _safe_init(lambda: DarkWebMonitor(alert_callback=None))

        self._build_ui()

        # Now safe to set callbacks (tk is fully initialized)
        try:
            if self._traffic_mon:
                self._traffic_mon.cb = self._on_traffic_update
        except Exception: pass
        try:
            if self._dw_monitor:
                self._dw_monitor.cb = self._on_dw_alert
        except Exception: pass

        try:
            ip = detect_local_ip()
            self.ip_var.set(ip)
            self._log("[SYSTEM] Logged in as: " + logged_in_user.upper(), "cyan")
            self._log("[SYSTEM] Auto-detected IP: " + ip, "green")
            self._log("[SYSTEM] CyberShield Pro v11.0 ready.", "dim")
            self._set_status(
                self.L.get("welcome","Welcome") + ", " + logged_in_user +
                "  ●  IP: " + ip + "  ●  " + self.L.get("ready","READY"))
        except Exception: pass

        try:
            if self.sys_monitor:
                self.sys_monitor.add_callback(self._on_monitor_update)
        except Exception: pass

        self.protocol("WM_DELETE_WINDOW", self._on_close)


    def _dash_refresh(self):
        """Update dashboard stats."""
        try:
            data  = score_history_graph.load_graph_data()
            stats = score_history_graph.get_stats(data)
            count = stats.get("count", 0)
            if count > 0:
                try:
                    self.graph_stats_var.set(
                        str(count) + " scans  |  Latest: " +
                        str(stats.get("latest","--")) + "  (" +
                        str(stats.get("latest_level","--")) + ")")
                    self._dash_widgets["scan_count"].configure(text=str(count))
                except Exception: pass
            W = self.dash_score_canvas.winfo_width() or 280
            H = self.dash_score_canvas.winfo_height() or 120
            score_history_graph.draw_graph(self.dash_score_canvas, data, W, H)
        except Exception: pass
        if self.risk_result:
            try:
                sc = self.risk_result.get("risk_score",0)
                lv = self.risk_result.get("risk_level","--")
                colors = {"CRITICAL":T["RED"],"HIGH":T["ORANGE"],"MEDIUM":T["YELLOW"],"LOW":T["GREEN"]}
                c = colors.get(lv, T["CYAN"])
                self._dash_widgets["risk_score"].configure(text=str(sc), fg=c)
                self._dash_widgets["risk_level"].configure(text=lv, fg=c)
            except Exception: pass
        if self.scan_results:
            try:
                ports = len(self.scan_results.get("open_ports",[]))
                self._dash_widgets["open_ports"].configure(text=str(ports),
                    fg=T["RED"] if ports>3 else T["ORANGE"] if ports>0 else T["GREEN"])
            except Exception: pass

    def _dash_update_traffic(self):
        """Update traffic display on dashboard."""
        try:
            data = getattr(self, "_dash_traffic_data", {})
            if not data: return
            sent = data.get("sent_rate", 0)
            recv = data.get("recv_rate", 0)
            self._dash_sent.configure(
                text="UP " + str(round(sent,1)) + " KB/s",
                fg=T["GREEN"] if sent<100 else T["ORANGE"])
            self._dash_recv.configure(
                text="DN " + str(round(recv,1)) + " KB/s",
                fg=T["CYAN"] if recv<100 else T["YELLOW"])
        except Exception: pass


    def _run_scan(self):
        self._on_scan()

    def _gen_pdf(self):
        if not self.scan_results:
            messagebox.showwarning("PDF", "Run a scan first!")
            return
        try:
            from report_gen import ReportGenerator
            rg = ReportGenerator(self.scan_results, self.risk_result)
            path = rg.generate_pdf()
            if path:
                messagebox.showinfo("PDF Report", "Saved: " + path)
                try:
                    import os; os.startfile(path)
                except Exception:
                    pass
            else:
                messagebox.showerror("PDF", "PDF generation failed")
        except Exception as e:
            messagebox.showerror("PDF Error", str(e))

    def _email_report(self):
        try:
            self._on_email()
        except Exception:
            messagebox.showinfo("Email", "Configure email in Settings tab.")

    def _on_close(self):
        # Disable custom titlebar before destroy to prevent Tcl issues
        try:
            self.overrideredirect(False)
        except Exception:
            pass
        # Stop all background services
        for svc_name, svc in [
            ("sys_monitor",  self.sys_monitor),
            ("alert_system", self.alert_system),
            ("usb_monitor",  self.usb_monitor),
            ("scheduler",    self.scheduler),
            ("traffic_mon",  self._traffic_mon),
            ("dw_monitor",   self._dw_monitor),
        ]:
            try:
                svc.stop()
            except Exception:
                pass
        try:
            self.destroy()
        except Exception:
            pass

    # ── LANGUAGE + THEME ─────────────────────────────────────────────────

    def _toggle_lang(self):
        self.current_lang = "ur" if self.current_lang=="en" else "en"
        self.L = LANG[self.current_lang]
        self.lang_btn.configure(text=self.L["lang_toggle"])
        messagebox.showinfo("Language / زبان",
            "English activated!" if self.current_lang=="en"
            else "اردو فعال ہو گئی!\nApplication restart for full effect.")

    def _toggle_theme(self, theme_name: str = None):
        global T, RISK_COLORS
        cycle = ["dark","light","day","night","purple","matrix","ocean"]
        if theme_name:
            self.current_theme = theme_name
        else:
            idx = cycle.index(self.current_theme) if self.current_theme in cycle else 0
            self.current_theme = cycle[(idx+1) % len(cycle)]
        T = THEMES.get(self.current_theme, THEMES["dark"])
        if self.current_theme == "light":
            RISK_COLORS={"CRITICAL":"#DE350B","HIGH":"#FF8B00","MEDIUM":"#FF991F","LOW":"#00875A"}
        else:
            RISK_COLORS={"CRITICAL":"#FF2D55","HIGH":"#FF8C42","MEDIUM":"#FFD60A","LOW":"#00FF88"}
        theme_labels = {"dark":"🌙 DARK","light":"☀ LIGHT","day":"☀ DAY","night":"🌙 NIGHT","purple":"🔮 PURPLE","matrix":"💻 MATRIX","ocean":"🌊 OCEAN"}
        self.theme_btn.configure(text=theme_labels.get(self.current_theme,"THEME"))
        # Save setting
        try: save_app_settings({"theme":self.current_theme,"language":self.current_lang})
        except Exception: pass
        messagebox.showinfo("Theme",f"Theme changed to: {self.current_theme.upper()}")

    # ── BUILD UI ─────────────────────────────────────────────────────────

    def _ui(self, func):
        """Thread-safe UI update — call from ANY thread."""
        # If not in main thread, only queue if mainloop is ready
        # Never WAIT — that causes Tcl_AsyncDelete crash
        if not threading.current_thread() is threading.main_thread():
            if not self._mainloop_ready.is_set():
                return  # silently drop — mainloop not ready yet
        self._ui_queue.put(func)

    def _poll_ui_queue(self):
        """Drain UI queue in main thread — runs every 20ms."""
        # Signal that mainloop is running
        if not self._mainloop_ready.is_set():
            self._mainloop_ready.set()
        try:
            while True:
                func = self._ui_queue.get_nowait()
                try:
                    func()
                except Exception:
                    pass
        except _queue.Empty:
            pass
        except Exception:
            pass
        try:
            self.after(20, self._poll_ui_queue)
        except Exception:
            pass

    def _start_background_services(self):
        """Start ALL background threads safely after mainloop is running."""
        services = [
            ('traffic_mon',  lambda: self._traffic_mon.start()),
            ('dw_monitor',   lambda: self._dw_monitor.start()),
            ('sys_monitor',  lambda: self.sys_monitor.start()),
            ('alert_system', lambda: self.alert_system.start()),
            ('usb_monitor',  lambda: self.usb_monitor.start()),
            ('scheduler',    lambda: self.scheduler.start()),
        ]
        for name, start_fn in services:
            try:
                start_fn()
            except Exception:
                pass

    def _safe_after(self, ms, func):
        """Thread-safe self.after() wrapper."""
        try:
            self.after(ms, func)
        except RuntimeError:
            pass

    def _build_ui(self):
        self._build_titlebar()
        self._build_header()
        self._build_body()
        self._build_statusbar()
        # Start queue poll FIRST — enables thread-safe _ui() calls
        self.after(10, self._poll_ui_queue)
        # Animate header gradient
        self.after(100, self._animate_header)
        # Start background services after mainloop is live
        self.after(400, self._start_background_services)
        # Start live threat score
        self.after(2000, self._update_threat_score)
        # Auto scan on startup
        self.after(3500, self._auto_startup_scan)


    # ══════════════════════════════════════════════════════════════════════
    # CUSTOM TITLE BAR
    # ══════════════════════════════════════════════════════════════════════
    def _build_titlebar(self):
        tb = tk.Frame(self, bg="#010D1A", height=36); tb.pack(fill=tk.X)
        tb.pack_propagate(False)
        tk.Label(tb, text="🛡", font=("Segoe UI Emoji",14),
                 bg="#010D1A", fg=T["CYAN"]).pack(side=tk.LEFT, padx=(10,4))
        tk.Label(tb, text="CYBERSHIELD PRO  v11.0  ·  AI VULNERABILITY ASSESSMENT",
                 font=("Consolas",9,"bold"), bg="#010D1A", fg=T["CYAN"]).pack(side=tk.LEFT)
        # Threat score badge
        self._threat_lbl = tk.Label(tb, text="⚡ THREAT: -- [SAFE]",
                                     font=("Consolas",8,"bold"), bg="#010D1A", fg=T["GREEN"])
        self._threat_lbl.pack(side=tk.LEFT, padx=20)
        # Window controls
        ctrl = tk.Frame(tb, bg="#010D1A"); ctrl.pack(side=tk.RIGHT)
        def _close(): self._on_close()
        def _minimize():
            self.overrideredirect(False); self.iconify()
            self.bind("<Map>", lambda e: (self.deiconify(), self.overrideredirect(True)))
        def _maximize():
            self._win_maximized = not self._win_maximized
            if self._win_maximized:
                self.geometry(f"{self.winfo_screenwidth()}x{self.winfo_screenheight()}+0+0")
                max_btn.configure(text="❐")
            else:
                self.geometry("1350x900"); max_btn.configure(text="□")

        close_btn = tk.Button(ctrl, text="✕", font=("Consolas",11,"bold"),
                              bg="#010D1A", fg="#FF2D55", relief=tk.FLAT, width=4,
                              cursor="hand2", command=_close)
        close_btn.pack(side=tk.RIGHT)
        close_btn.bind("<Enter>", lambda e: close_btn.configure(bg="#FF2D55", fg="white"))
        close_btn.bind("<Leave>", lambda e: close_btn.configure(bg="#010D1A", fg="#FF2D55"))
        max_btn = tk.Button(ctrl, text="□", font=("Consolas",11), bg="#010D1A",
                            fg=T["TEXT_DIM"], relief=tk.FLAT, width=4, cursor="hand2",
                            command=_maximize)
        max_btn.pack(side=tk.RIGHT)
        max_btn.bind("<Enter>", lambda e: max_btn.configure(bg=T["BG_ELEVATED"]))
        max_btn.bind("<Leave>", lambda e: max_btn.configure(bg="#010D1A"))
        min_btn = tk.Button(ctrl, text="−", font=("Consolas",12,"bold"), bg="#010D1A",
                            fg=T["TEXT_DIM"], relief=tk.FLAT, width=4, cursor="hand2",
                            command=_minimize)
        min_btn.pack(side=tk.RIGHT)
        min_btn.bind("<Enter>", lambda e: min_btn.configure(bg=T["BG_ELEVATED"]))
        min_btn.bind("<Leave>", lambda e: min_btn.configure(bg="#010D1A"))
        tk.Button(ctrl, text="⬇ TRAY", font=("Consolas",8), bg="#010D1A",
                  fg=T["TEXT_DIM"], relief=tk.FLAT, padx=6, cursor="hand2",
                  command=self._minimize_to_tray).pack(side=tk.RIGHT, padx=6)
        # Drag support
        def _start(e): self._drag_x = e.x_root - self.winfo_x(); self._drag_y = e.y_root - self.winfo_y()
        def _drag(e):
            if not self._win_maximized and APP_CONFIG.get("custom_titlebar"):
                try:
                    self.geometry(f"+{e.x_root-self._drag_x}+{e.y_root-self._drag_y}")
                except Exception:
                    pass
        tb.bind("<Button-1>", _start); tb.bind("<B1-Motion>", _drag)
        for child in tb.winfo_children():
            if isinstance(child, tk.Label):
                child.bind("<Button-1>", _start); child.bind("<B1-Motion>", _drag)
        # Animated gradient bar
        self._tb_canvas = tk.Canvas(self, height=3, bg=T["BG_DEEP"], highlightthickness=0)
        self._tb_canvas.pack(fill=tk.X)
        self._tb_pos = 0

    def _animate_header(self):
        try:
            c = self._tb_canvas; w = c.winfo_width()
            if w < 10: self.after(200, self._animate_header); return
            c.delete("all")
            colors = [T["CYAN"], "#00FF88", "#AA44FF", T["ORANGE"], T["CYAN"]]
            seg = max(1, w // (len(colors)-1)); pos = self._tb_pos % w
            for i in range(w):
                idx2 = (i + pos) % w; ci = min(idx2 // seg, len(colors)-2)
                r2 = (idx2 % seg) / seg
                def lerp(h1, h2, t):
                    r1,g1,b1 = int(h1[1:3],16),int(h1[3:5],16),int(h1[5:7],16)
                    r2b,g2b,b2b = int(h2[1:3],16),int(h2[3:5],16),int(h2[5:7],16)
                    return "#{:02x}{:02x}{:02x}".format(int(r1+(r2b-r1)*t),int(g1+(g2b-g1)*t),int(b1+(b2b-b1)*t))
                c.create_line(i, 0, i, 3, fill=lerp(colors[ci], colors[ci+1], r2))
            self._tb_pos = (self._tb_pos + 4) % w
            self.after(40, self._animate_header)
        except Exception:
            pass

    def _update_threat_score(self):
        try:
            import psutil
            cpu = psutil.cpu_percent(); ram = psutil.virtual_memory().percent
            conns = len([c for c in psutil.net_connections() if c.status == "ESTABLISHED"])
            score = min(100, int(cpu*0.2 + ram*0.15 + conns*0.5 + 10))
            level = "CRITICAL" if score>75 else "HIGH" if score>50 else "MEDIUM" if score>25 else "SAFE"
            color = {"CRITICAL":"#FF2D55","HIGH":"#FF8C42","MEDIUM":"#FFD60A","SAFE":"#00FF88"}.get(level, T["CYAN"])
            self._threat_score = score; self._threat_level = level
            self._threat_lbl.configure(text="THREAT: " + str(score) + "  [" + str(level) + "]", fg=color)
        except Exception:
            pass
        self.after(8000, self._update_threat_score)

    def _auto_startup_scan(self):
        self._set_status("🔄 Startup auto-check running...")
        self._log("[AUTO-SCAN] Quick startup check triggered", "cyan")
        self.after(2500, lambda: self._set_status(
            f"welcome, {self.logged_in_user}  ●  IP: {self.ip_var.get()}  ●  SYSTEM READY"))

    def _build_body(self):
        body = tk.Frame(self, bg=T["BG_DEEP"]); body.pack(fill=tk.BOTH, expand=True)
        self._build_sidebar(body)
        content = tk.Frame(body, bg=T["BG_DEEP"]); content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._build_notebook_in(content)

    def _build_notebook_in(self, parent):
        sty = ttk.Style(); sty.theme_use("clam")
        sty.configure("Cyber.TNotebook", background=T["BG_DEEP"], borderwidth=0)
        sty.configure("Cyber.TNotebook.Tab", background=T["BG_PANEL"],
                       foreground=T["TEXT_DIM"], padding=[10,7], font=("Consolas",7,"bold"))
        sty.map("Cyber.TNotebook.Tab",
                background=[("selected", T["BG_ELEVATED"])],
                foreground=[("selected", T["CYAN"])])
        self.nb = ttk.Notebook(parent, style="Cyber.TNotebook")
        self.nb.pack(fill=tk.BOTH, expand=True)
        ICONS = {
            "scanner":"🔍","network":"🌐","monitor":"📊","password":"🔑",
            "firewall":"🧱","autofix":"🔧","alerts":"🔔","schedule":"⏰",
            "hardening":"🛡","threatmap":"🗺","seclab":"🔬","history":"📜",
            "wifi":"📡","malware":"🦠","usb":"🔌","breach":"💔","report_card":"📋",
            "ctf":"🏆","2fa":"🔐","speedtest":"⚡","scoregraph":"📈",
            "processes":"⚙","iplookup":"🌍","pwvault":"🗄","home_dashboard":"🏠",
            "timeline":"📅","traffic":"📶","darkweb":"🌑","cve":"⚠","backup":"💾",
            "wifi_pw":"🔑","vpn":"🔒","phishing":"🎣","ransomware":"💀",
            "rogue_ap":"📡","keylogger":"⌨","port_knock":"🚪","disk":"💿",
            "netconn":"🌐","loginlog":"👤","battery":"🔋","hashtools":"#️⃣",
            "attack_sim":"⚔","news":"📰","ai_chat":"🤖","pwgen":"🎲","uptime":"⏱","sys_dash":"🖥","net_dash":"🌐",
            "nmap":"🗺","defender":"🛡","stego":"👁","echat":"🔐",
            "packets":"📡","hashcrack":"🔓","soceng":"🎭","msf":"💀",
            "analytics":"📊",
        }
        builders = [
            (self.L["tab_scanner"],   self._tab_scanner,        "scanner"),
            (self.L["tab_network"],   self._tab_network,        "network"),
            (self.L["tab_monitor"],   self._tab_monitor,        "monitor"),
            (self.L["tab_password"],  self._tab_password,       "password"),
            (self.L["tab_firewall"],  self._tab_firewall,       "firewall"),
            (self.L["tab_autofix"],   self._tab_autofix,        "autofix"),
            (self.L["tab_alerts"],    self._tab_alerts,         "alerts"),
            (self.L["tab_schedule"],  self._tab_schedule,       "schedule"),
            (self.L["tab_hardening"], self._tab_hardening,      "hardening"),
            (self.L["tab_threatmap"], self._tab_threatmap,      "threatmap"),
            (self.L["tab_seclab"],    self._tab_seclab,         "seclab"),
            (self.L["tab_history"],   self._tab_history,        "history"),
            ("WiFi SCANNER",          self._tab_wifi,           "wifi"),
            ("MALWARE SCAN",          self._tab_malware,        "malware"),
            ("USB MONITOR",           self._tab_usb,            "usb"),
            ("BREACH CHECK",          self._tab_breach,         "breach"),
            ("REPORT CARD",           self._tab_report_card,    "report_card"),
            ("CTF CHALLENGES",        self._tab_ctf,            "ctf"),
            ("2FA SETUP",             self._tab_2fa,            "2fa"),
            ("SPEED TEST",            self._tab_speedtest,      "speedtest"),
            ("SCORE GRAPH",           self._tab_scoregraph,     "scoregraph"),
            ("PROCESSES",             self._tab_processes,      "processes"),
            ("IP LOOKUP",             self._tab_iplookup,       "iplookup"),
            ("PASSWORD VAULT",        self._tab_pwvault,        "pwvault"),
            ("DASHBOARD",             self._tab_home_dashboard, "home_dashboard"),
            ("TIMELINE",              self._tab_timeline,       "timeline"),
            ("TRAFFIC GRAPH",         self._tab_traffic,        "traffic"),
            ("DARK WEB",              self._tab_darkweb,        "darkweb"),
            ("CVE SEARCH",            self._tab_cve,            "cve"),
            ("BACKUP",                self._tab_backup,         "backup"),
            ("WiFi PASSWORDS",        self._tab_wifi_pw,        "wifi_pw"),
            ("VPN STATUS",            self._tab_vpn,            "vpn"),
            ("PHISHING CHECK",        self._tab_phishing,       "phishing"),
            ("RANSOMWARE SCAN",       self._tab_ransomware,     "ransomware"),
            ("ROGUE AP",              self._tab_rogue_ap,       "rogue_ap"),
            ("KEYLOGGER SCAN",        self._tab_keylogger,      "keylogger"),
            ("PORT KNOCKING",         self._tab_port_knock,     "port_knock"),
            ("DISK ANALYZER",         self._tab_disk,           "disk"),
            ("NET CONNECTIONS",       self._tab_netconn,        "netconn"),
            ("LOGIN LOGGER",          self._tab_loginlog,       "loginlog"),
            ("BATTERY & UPTIME",      self._tab_battery,        "battery"),
            ("HASH TOOLS",            self._tab_hashtools,      "hashtools"),
            ("ATTACK SIM",            self._tab_attack_sim,     "attack_sim"),
            ("SECURITY NEWS",         self._tab_news,           "news"),
            ("AI CHAT",               self._tab_ai_chat,        "ai_chat"),
            ("PW GENERATOR",          self._tab_pwgen,          "pwgen"),
            ("SYS DASHBOARD",         self._tab_sys_dashboard,  "sys_dash"),
            ("NET DASHBOARD",         self._tab_net_dashboard,  "net_dash"),
            ("NMAP SCANNER",          self._tab_nmap,           "nmap"),
            ("WIN DEFENDER",          self._tab_defender,       "defender"),
            ("STEGO DETECT",          self._tab_stego,          "stego"),
            ("ENCRYPT CHAT",          self._tab_echat,          "echat"),
            ("PACKET LIVE",           self._tab_packets,        "packets"),
            ("HASH CRACKER",          self._tab_hashcrack,      "hashcrack"),
            ("SOCIAL ENG",            self._tab_soceng,         "soceng"),
            ("METASPLOIT",            self._tab_msf,            "msf"),
            ("ANALYTICS",             self._tab_analytics,      "analytics"),
        ]
        for title, builder, key in builders:
            icon = ICONS.get(key, "◈")
            tab_text = " " + icon + " " + title + " "
            f = tk.Frame(self.nb, bg=T["BG_DEEP"])
            self.nb.add(f, text=tab_text)
            try:
                builder(f)
            except Exception as _tab_err:
                import traceback, logging
                tb = traceback.format_exc()
                logging.getLogger(__name__).warning(
                    "Tab '" + title + "' error: " + str(_tab_err) + "\n" + tb[:300])
                # Show clean placeholder — NOT a popup
                err_frame = tk.Frame(f, bg=T["BG_DEEP"])
                err_frame.pack(fill=tk.BOTH, expand=True)
                tk.Label(err_frame, text="⚠",
                         font=("Segoe UI Emoji",40), bg=T["BG_DEEP"],
                         fg=T["ORANGE"]).pack(pady=(60,10))
                tk.Label(err_frame, text=title + " — Loading Error",
                         font=("Consolas",12,"bold"), bg=T["BG_DEEP"],
                         fg=T["ORANGE"]).pack()
                tk.Label(err_frame, text=str(_tab_err)[:120],
                         font=("Consolas",9), bg=T["BG_DEEP"],
                         fg=T["TEXT_DIM"], wraplength=600).pack(pady=8)
                tk.Button(err_frame, text="🔄 Retry",
                          font=("Consolas",10,"bold"),
                          bg=T["CYAN"], fg=T["BG_DEEP"],
                          relief=tk.FLAT, cursor="hand2",
                          padx=16, pady=8,
                          command=lambda _f=f, _b=builder: (
                              [w.destroy() for w in _f.winfo_children()],
                              _b(_f)
                          )).pack()

    def _build_header(self):
        hdr = tk.Frame(self, bg=T["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=T["CYAN"], height=3).pack(fill=tk.X)
        inner = tk.Frame(hdr, bg=T["BG_PANEL"], padx=16, pady=10); inner.pack(fill=tk.X)

        left = tk.Frame(inner, bg=T["BG_PANEL"]); left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(left, text=f"◈  {self.L['app_title']}",
                 font=("Consolas",14,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"]).pack(anchor="w")
        tk.Label(left, text=self.L["subtitle"],
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"]).pack(anchor="w")

        right = tk.Frame(inner, bg=T["BG_PANEL"]); right.pack(side=tk.RIGHT)
        tk.Label(right, text=f"👤 {self.logged_in_user.upper()}",
                 font=("Consolas",9,"bold"), bg=T["BG_PANEL"], fg=T["GREEN"]).pack(anchor="e")

        btn_row = tk.Frame(right, bg=T["BG_PANEL"]); btn_row.pack(anchor="e", pady=4)
        self.lang_btn = tk.Button(btn_row, text=self.L["lang_toggle"],
                                   font=("Consolas",8), bg=T["BG_CARD"], fg=T["CYAN"],
                                   relief=tk.FLAT, cursor="hand2", padx=8, pady=3,
                                   command=self._toggle_lang)
        self.lang_btn.pack(side=tk.LEFT, padx=2)
        self.theme_btn = tk.Button(btn_row, text=self.L["theme_light"],
                                    font=("Consolas",8), bg=T["BG_CARD"], fg=T["CYAN"],
                                    relief=tk.FLAT, cursor="hand2", padx=8, pady=3,
                                    command=self._toggle_theme)
        self.theme_btn.pack(side=tk.LEFT, padx=2)

        # Alert badge
        self.alert_badge = tk.Label(right, text="🔔 0 ALERTS",
                                     font=("Consolas",8,"bold"),
                                     bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                                     padx=8, pady=3, cursor="hand2")
        self.alert_badge.pack(anchor="e")
        tk.Frame(hdr, bg=T["BG_ELEVATED"], height=1).pack(fill=tk.X)


    def _tab_scanner(self, parent):
        """Redesigned professional scanner with live panels."""
        # ── Top control strip ──────────────────────────────────────────
        ctrl = tk.Frame(parent, bg=T["BG_PANEL"], pady=0); ctrl.pack(fill=tk.X)
        # Gradient top bar
        grad = tk.Canvas(ctrl, height=4, bg=T["BG_DEEP"], highlightthickness=0)
        grad.pack(fill=tk.X)
        grad.bind("<Configure>", lambda e: self._draw_scan_gradient(grad))
        self._scan_grad_canvas = grad

        bar = tk.Frame(ctrl, bg=T["BG_PANEL"], padx=14, pady=10); bar.pack(fill=tk.X)

        # Target IP
        tk.Label(bar, text="TARGET", font=("Consolas",7,"bold"),
                 bg=T["BG_PANEL"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,4))
        ipf = tk.Frame(bar, bg=T["CYAN"], padx=2, pady=2); ipf.pack(side=tk.LEFT)
        self.ip_var = tk.StringVar(value="127.0.0.1")
        ip_entry = tk.Entry(ipf, textvariable=self.ip_var,
                            font=("Consolas",13,"bold"), width=17,
                            bg=T["BG_DEEP"], fg=T["GREEN"],
                            insertbackground=T["GREEN"], relief=tk.FLAT, bd=5)
        ip_entry.pack()

        tk.Button(bar, text="⟳ DETECT", font=("Consolas",8,"bold"),
                  bg=T["BG_CARD"], fg=T["CYAN"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=6, command=self._redetect_ip).pack(side=tk.LEFT, padx=6)

        # Scan button (large)
        self.btn_scan = tk.Button(bar, text="▶  INITIATE SCAN",
                                   font=("Consolas",11,"bold"),
                                   bg=T["CYAN"], fg=T["BG_DEEP"],
                                   activebackground="#00FFFF",
                                   relief=tk.FLAT, cursor="hand2",
                                   padx=20, pady=6,
                                   command=self._run_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=4)

        self.btn_report = tk.Button(bar, text="📄 EXPORT PDF",
                                     font=("Consolas",9,"bold"),
                                     bg=T["GREEN_DIM"], fg=T["BG_DEEP"],
                                     relief=tk.FLAT, cursor="hand2",
                                     padx=12, pady=6,
                                     state=tk.DISABLED,
                                     command=self._gen_pdf)
        self.btn_report.pack(side=tk.LEFT, padx=4)

        self.btn_email = tk.Button(bar, text="✉ EMAIL",
                                    font=("Consolas",9),
                                    bg=T["BG_ELEVATED"], fg=T["CYAN"],
                                    relief=tk.FLAT, cursor="hand2",
                                    padx=10, pady=6,
                                    state=tk.DISABLED,
                                    command=self._email_report)
        self.btn_email.pack(side=tk.LEFT, padx=2)

        tk.Button(bar, text="✕ CLEAR", font=("Consolas",8),
                  bg=T["BG_CARD"], fg=T["TEXT_DIM"], relief=tk.FLAT,
                  cursor="hand2", padx=8, pady=6,
                  command=self._clear).pack(side=tk.LEFT, padx=2)

        # Status pill
        self.scan_status_pill = tk.Label(bar, text="● IDLE",
                                          font=("Consolas",9,"bold"),
                                          bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                                          padx=10, pady=4)
        self.scan_status_pill.pack(side=tk.RIGHT)

        # ── MAIN BODY ──────────────────────────────────────────────────
        body = tk.Frame(parent, bg=T["BG_DEEP"]); body.pack(fill=tk.BOTH, expand=True)

        # ── Left panel: Log + Risk Factors ────────────────────────────
        left = tk.Frame(body, bg=T["BG_DEEP"]); left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Log header
        log_hdr = tk.Frame(left, bg=T["BG_PANEL"], pady=6, padx=14)
        log_hdr.pack(fill=tk.X)
        tk.Label(log_hdr, text="▌ SCAN OUTPUT  //  LIVE ANALYSIS LOG",
                 font=("Consolas",9,"bold"), bg=T["BG_PANEL"],
                 fg=T["CYAN"]).pack(side=tk.LEFT)
        self.scan_idle_lbl = tk.Label(log_hdr, text="● IDLE",
                                       font=("Consolas",8,"bold"),
                                       bg=T["BG_PANEL"], fg=T["TEXT_DIM"])
        self.scan_idle_lbl.pack(side=tk.RIGHT)

        # Log area
        log_frame = tk.Frame(left, bg=T["LOG_BG"]); log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_area = tk.Text(log_frame, font=("Consolas",10),
                                bg=T["LOG_BG"], fg=T["TEXT_MID"],
                                insertbackground=T["CYAN"],
                                relief=tk.FLAT, padx=12, pady=10,
                                state=tk.DISABLED, wrap=tk.WORD)
        log_vsb = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_area.yview)
        self.log_area.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_area.pack(fill=tk.BOTH, expand=True)

        # Log tags
        for tag, color, bold in [
            ("red",    T["RED"],    True),
            ("orange", T["ORANGE"], False),
            ("green",  T["GREEN"],  True),
            ("cyan",   T["CYAN"],   False),
            ("dim",    T["TEXT_DIM"],False),
            ("white",  T["TEXT_BRIGHT"],False),
        ]:
            self.log_area.tag_configure(
                tag, foreground=color,
                font=("Consolas",10,"bold" if bold else "normal"))

        # ── Risk factor analysis strip ─────────────────────────────────
        risk_panel = tk.Frame(left, bg=T["BG_PANEL"], padx=14, pady=10)
        risk_panel.pack(fill=tk.X)
        tk.Label(risk_panel, text="RISK FACTOR ANALYSIS",
                 font=("Consolas",8,"bold"), bg=T["BG_PANEL"],
                 fg=T["CYAN_DIM"]).pack(anchor="w", pady=(0,6))

        factors_grid = tk.Frame(risk_panel, bg=T["BG_PANEL"])
        factors_grid.pack(fill=tk.X)

        self.f_bars = {}; self.f_lbls = {}
        factors = [
            ("OPEN PORTS (25%)", "port_score"),
            ("FIREWALL (25%)",   "fw_score"),
            ("OS UPDATES (20%)", "os_score"),
            ("ANTIVIRUS (20%)",  "av_score"),
            ("CRITICAL PORTS (10%)","crit_score"),
        ]
        for idx, (label, key) in enumerate(factors):
            col = idx % 3; row = idx // 3
            cell = tk.Frame(factors_grid, bg=T["BG_PANEL"])
            cell.grid(row=row, column=col, sticky="ew", padx=6, pady=2)
            factors_grid.columnconfigure(col, weight=1)
            tk.Label(cell, text=label, font=("Consolas",7),
                     bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
            bar_row = tk.Frame(cell, bg=T["BG_PANEL"]); bar_row.pack(fill=tk.X)
            bar = MiniBar(bar_row, width=140, height=10, bg=T["BG_PANEL"])
            bar.pack(side=tk.LEFT)
            lbl = tk.Label(bar_row, text="--", font=("Consolas",8,"bold"),
                          bg=T["BG_PANEL"], fg=T["TEXT_DIM"], width=5)
            lbl.pack(side=tk.LEFT, padx=4)
            self.f_bars[key] = bar; self.f_lbls[key] = lbl

        # ── Right panel: Risk Meter + System Info ──────────────────────
        right = tk.Frame(body, bg=T["BG_PANEL"], width=280)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)

        # Risk meter
        rm_hdr = tk.Frame(right, bg=T["BG_ELEVATED"], padx=12, pady=8)
        rm_hdr.pack(fill=tk.X)
        tk.Label(rm_hdr, text="THREAT LEVEL", font=("Consolas",9,"bold"),
                 bg=T["BG_ELEVATED"], fg=T["TEXT_DIM"]).pack()

        meter_frame = tk.Frame(right, bg=T["BG_PANEL"], pady=10)
        meter_frame.pack(fill=tk.X)
        self.risk_meter = RiskMeter(meter_frame, size=200, bg=T["BG_PANEL"])
        self.risk_meter.pack()

        # Security indicators
        si_frame = tk.Frame(right, bg=T["BG_PANEL"], padx=14, pady=8)
        si_frame.pack(fill=tk.X)
        tk.Label(si_frame, text="SECURITY STATUS", font=("Consolas",8,"bold"),
                 bg=T["BG_PANEL"], fg=T["CYAN_DIM"]).pack(anchor="w", pady=(0,6))
        self.sec_ind = {}
        for label in ["FIREWALL", "ANTIVIRUS", "UPDATES"]:
            row2 = tk.Frame(si_frame, bg=T["BG_PANEL"]); row2.pack(fill=tk.X, pady=2)
            tk.Label(row2, text=label, font=("Consolas",8),
                     bg=T["BG_PANEL"], fg=T["TEXT_DIM"], width=12, anchor="w").pack(side=tk.LEFT)
            dot = tk.Label(row2, text="...", font=("Consolas",8,"bold"),
                          bg=T["BG_PANEL"], fg=T["TEXT_DIM"])
            dot.pack(side=tk.RIGHT)
            self.sec_ind[label.lower()] = dot

        # Divider
        tk.Frame(right, bg=T["BG_ELEVATED"], height=1).pack(fill=tk.X, padx=12)

        # System info
        sif = tk.Frame(right, bg=T["BG_PANEL"], padx=14, pady=8)
        sif.pack(fill=tk.X)
        tk.Label(sif, text="SYSTEM INFO", font=("Consolas",8,"bold"),
                 bg=T["BG_PANEL"], fg=T["CYAN_DIM"]).pack(anchor="w", pady=(0,6))
        self._si_widgets = {}
        for label, key in [("IP:", "ip"), ("HOST:", "host"), ("OS:", "os")]:
            row3 = tk.Frame(sif, bg=T["BG_PANEL"]); row3.pack(fill=tk.X, pady=2)
            tk.Label(row3, text=label, font=("Consolas",8,"bold"),
                     bg=T["BG_PANEL"], fg=T["TEXT_DIM"], width=7, anchor="w").pack(side=tk.LEFT)
            lbl2 = tk.Label(row3, text="--", font=("Consolas",9,"bold"),
                           bg=T["BG_PANEL"], fg=T["CYAN"], anchor="w")
            lbl2.pack(side=tk.LEFT)
            self._si_widgets[key] = lbl2

        # AI Agent panel
        ai_frame = tk.Frame(right, bg=T["BG_ELEVATED"], padx=12, pady=10)
        ai_frame.pack(fill=tk.X, padx=0)
        tk.Frame(ai_frame, bg="#AA44FF", height=2).pack(fill=tk.X, pady=(0,6))
        tk.Label(ai_frame, text="🤖 AI AGENT", font=("Consolas",9,"bold"),
                 bg=T["BG_ELEVATED"], fg="#AA44FF").pack(anchor="w")
        self.ai_agent_lbl = tk.Label(ai_frame,
                                      text="Ready — run scan to activate",
                                      font=("Consolas",8), bg=T["BG_ELEVATED"],
                                      fg=T["TEXT_DIM"], wraplength=220,
                                      justify="left", anchor="w")
        self.ai_agent_lbl.pack(fill=tk.X, pady=4)
        tk.Button(ai_frame, text="💬 ASK AI AGENT", font=("Consolas",8,"bold"),
                  bg="#AA44FF", fg="white", relief=tk.FLAT, cursor="hand2",
                  pady=5, command=self._open_ai_agent).pack(fill=tk.X)

        # Populate system info
        self.after(200, self._populate_sysinfo)
        self.after(300, lambda: self._draw_scan_gradient(grad))

    def _draw_scan_gradient(self, canvas):
        try:
            canvas.delete("all")
            w = canvas.winfo_width()
            if w < 2: return
            colors = [T["CYAN"], T["GREEN"], "#AA44FF", T["ORANGE"], T["CYAN"]]
            seg = max(1, w // (len(colors)-1))
            for i in range(w):
                ci  = min(i // seg, len(colors)-2)
                rat = (i % seg) / seg
                def lerp(h1,h2,t):
                    r1,g1,b1 = int(h1[1:3],16),int(h1[3:5],16),int(h1[5:7],16)
                    r2,g2,b2 = int(h2[1:3],16),int(h2[3:5],16),int(h2[5:7],16)
                    return "#{:02x}{:02x}{:02x}".format(
                        int(r1+(r2-r1)*t),int(g1+(g2-g1)*t),int(b1+(b2-b1)*t))
                canvas.create_line(i,0,i,4, fill=lerp(colors[ci],colors[ci+1],rat))
        except Exception:
            pass

    def _populate_sysinfo(self):
        try:
            import platform
            host = socket.gethostname()
            ip   = self.ip_var.get()
            os_s = platform.system() + " " + platform.release()
            try:
                self._si_widgets["ip"].configure(text=ip[:22])
                self._si_widgets["host"].configure(text=host[:22])
                self._si_widgets["os"].configure(text=os_s[:22])
            except Exception:
                pass
        except Exception:
            pass

    def _open_ai_agent(self):
        """Open AI agent dialog."""
        # Switch to AI Chat tab
        for i in range(self.nb.index("end")):
            tab_text = self.nb.tab(i,"text").upper()
            if "AI" in tab_text and "CHAT" in tab_text:
                self.nb.select(i)
                return
        # If no AI chat tab, show inline
        from tkinter import simpledialog
        q = simpledialog.askstring("AI Agent",
            "Ask the AI Security Agent anything:")
        if q:
            from ai_chat import get_ai_response
            r = get_ai_response(q)
            messagebox.showinfo("AI Agent — " + r.get("title",""),
                                r.get("answer","No response")[:500])


    def _tab_network(self, parent):
        hdr=tk.Frame(parent,bg=T["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr,bg=T["CYAN"],height=2).pack(fill=tk.X)
        row=tk.Frame(hdr,bg=T["BG_PANEL"],pady=10,padx=14); row.pack(fill=tk.X)
        tk.Label(row,text="◈  NETWORK MAP — CONNECTED DEVICES",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"]).pack(side=tk.LEFT)
        self.btn_netscan=tk.Button(row,text="▶  SCAN NETWORK",
                                    font=("Consolas",10,"bold"),bg=T["CYAN"],fg=T["BG_DEEP"],
                                    relief=tk.FLAT,cursor="hand2",padx=14,pady=6,
                                    command=self._on_net_scan)
        self.btn_netscan.pack(side=tk.RIGHT)
        sty2=ttk.Style()
        sty2.configure("N.Horizontal.TProgressbar",troughcolor=T["BG_CARD"],background=T["CYAN"],thickness=3)
        self.net_progress=ttk.Progressbar(row,mode="indeterminate",length=120,style="N.Horizontal.TProgressbar")
        self.net_progress.pack(side=tk.RIGHT,padx=12)
        self.net_stats=tk.StringVar(value="Click SCAN NETWORK to discover all connected devices")
        tk.Label(parent,textvariable=self.net_stats,font=("Consolas",9),
                 bg=T["BG_ELEVATED"],fg=T["CYAN"],anchor="w",padx=14,pady=6).pack(fill=tk.X)
        cols=("IP Address","MAC Address","Hostname","Device Type","Status")
        sty3=ttk.Style()
        sty3.configure("N.Treeview",background=T["BG_CARD"],foreground=T["TEXT_MID"],
                        fieldbackground=T["BG_CARD"],rowheight=28,font=("Consolas",9))
        sty3.configure("N.Treeview.Heading",background=T["BG_ELEVATED"],foreground=T["CYAN"],font=("Consolas",9,"bold"))
        tf=tk.Frame(parent,bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        self.net_tree=ttk.Treeview(tf,columns=cols,show="headings",style="N.Treeview")
        for col,w in zip(cols,[130,160,200,180,90]):
            self.net_tree.heading(col,text=col); self.net_tree.column(col,width=w,anchor="w")
        self.net_tree.tag_configure("local",foreground=T["GREEN"])
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.net_tree.yview)
        self.net_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.net_tree.pack(fill=tk.BOTH,expand=True)

    def _on_net_scan(self):
        if self.net_scanning: return
        self.net_scanning=True
        self.btn_netscan.configure(state=tk.DISABLED,text="◉ SCANNING...",bg=T["CYAN_DIM"])
        self.net_progress.start(10)
        for r in self.net_tree.get_children(): self.net_tree.delete(r)
        self.net_stats.set("Scanning... 30-60 seconds")
        threading.Thread(target=self._net_bg,daemon=True).start()

    def _net_bg(self):
        try:
            mapper=NetworkMapper(progress_callback=lambda m:self._log_safe(m,"dim"))
            devices=mapper.scan_network()
            self._ui(lambda:self._show_net(devices))
        except Exception as e:
            self._ui(lambda:self._log(f"[NET ERROR] {e}","red"))
        finally:
            self._ui(self._net_done)

    def _net_done(self):
        self.net_scanning=False; self.net_progress.stop()
        self.btn_netscan.configure(state=tk.NORMAL,text="▶  SCAN NETWORK",bg=T["CYAN"])

    def _show_net(self,devices):
        for r in self.net_tree.get_children(): self.net_tree.delete(r)
        for d in devices:
            self.net_tree.insert("","end",values=(d["ip"],d["mac"],d["hostname"],d["label"],d["status"]),
                                  tags=("local",) if d.get("is_local") else ())
        self.net_stats.set(f"✓ {len(devices)} device(s) found  ●  Subnet: {'.'.join(detect_local_ip().split('.')[:3])}.0/24")

    # ══════════════════════════════════════════════════════════════════════
    # TAB: SYSTEM MONITOR
    # ══════════════════════════════════════════════════════════════════════

    def _tab_monitor(self, parent):
        tk.Label(parent,text="  ◈  REAL-TIME SYSTEM PERFORMANCE DASHBOARD",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=2).pack(fill=tk.X)
        grid=tk.Frame(parent,bg=T["BG_DEEP"]); grid.pack(fill=tk.BOTH,expand=True,padx=10,pady=10)
        self.mon_w={}
        row1=tk.Frame(grid,bg=T["BG_DEEP"]); row1.pack(fill=tk.X)
        row2=tk.Frame(grid,bg=T["BG_DEEP"]); row2.pack(fill=tk.X)
        for parent_row,title,key,color in [
            (row1,"CPU USAGE","cpu",T["CYAN"]),(row1,"RAM / MEMORY","ram",T["GREEN"]),
            (row2,"DISK (C:)","disk",T["ORANGE"]),(row2,"NETWORK","net","#AA44FF")]:
            cf=tk.Frame(parent_row,bg=T["BG_DEEP"]); cf.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
            card=tk.Frame(cf,bg=T["BG_CARD"],padx=16,pady=12); card.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
            tk.Frame(card,bg=color,height=2).pack(fill=tk.X,pady=(0,8))
            tk.Label(card,text=title,font=("Consolas",9,"bold"),bg=T["BG_CARD"],fg=color,anchor="w").pack(fill=tk.X)
            pl=tk.Label(card,text="0%",font=("Consolas",28,"bold"),bg=T["BG_CARD"],fg=color); pl.pack(anchor="w")
            bar=MiniBar(card,width=220,height=14,color=color,bg=T["BG_CARD"]); bar.pack(anchor="w",pady=(4,6))
            sl=tk.Label(card,text="--",font=("Consolas",8),bg=T["BG_CARD"],fg=T["TEXT_DIM"]); sl.pack(anchor="w")
            self.mon_w[key]={"pct":pl,"bar":bar,"sub":sl,"color":color}
        info=tk.Frame(grid,bg=T["BG_CARD"],padx=14,pady=8); info.pack(fill=tk.X,padx=6,pady=6)
        tk.Frame(info,bg=T["CYAN"],height=1).pack(fill=tk.X,pady=(0,6))
        ir=tk.Frame(info,bg=T["BG_CARD"]); ir.pack(fill=tk.X)
        self.extra_lbl={}
        for key,label in [("processes","PROCESSES"),("boot_time","BOOT TIME"),("net_speed","NET SPEED")]:
            col=tk.Frame(ir,bg=T["BG_CARD"]); col.pack(side=tk.LEFT,fill=tk.X,expand=True)
            tk.Label(col,text=label,font=("Consolas",7),bg=T["BG_CARD"],fg=T["TEXT_DIM"]).pack()
            lbl=tk.Label(col,text="--",font=("Consolas",10,"bold"),bg=T["BG_CARD"],fg=T["CYAN"]); lbl.pack()
            self.extra_lbl[key]=lbl

    def _on_monitor_update(self,data):
        try:
            self._ui( lambda: self._update_mon(data))
        except RuntimeError: pass

    def _update_mon(self,data):
        try:
            if not hasattr(self,"mon_w") or not self.mon_w: return
            cpu=data.get("cpu_percent",0); ram=data.get("ram_percent",0); disk=data.get("disk_percent",0)
            cc=T["RED"] if cpu>80 else T["ORANGE"] if cpu>60 else T["CYAN"]
            rc=T["RED"] if ram>85 else T["ORANGE"] if ram>70 else T["GREEN"]
            dc=T["RED"] if disk>90 else T["ORANGE"] if disk>75 else T["ORANGE"]
            if "cpu" in self.mon_w:
                w=self.mon_w["cpu"]; w["pct"].configure(text=f"{cpu:.0f}%",fg=cc); w["bar"].set_value(cpu,cc)
                w["sub"].configure(text=f"Cores:{data.get('cpu_cores',0)}  Freq:{data.get('cpu_freq_mhz',0)}MHz")
            if "ram" in self.mon_w:
                w=self.mon_w["ram"]; w["pct"].configure(text=f"{ram:.0f}%",fg=rc); w["bar"].set_value(ram,rc)
                w["sub"].configure(text=f"Used:{data.get('ram_used_gb',0)}GB / Total:{data.get('ram_total_gb',0)}GB")
            if "disk" in self.mon_w:
                w=self.mon_w["disk"]; w["pct"].configure(text=f"{disk:.0f}%",fg=dc); w["bar"].set_value(disk,dc)
                w["sub"].configure(text=f"Used:{data.get('disk_used_gb',0)}GB / Total:{data.get('disk_total_gb',0)}GB")
            if "net" in self.mon_w:
                w=self.mon_w["net"]; nr=data.get("net_recv_mb",0)
                w["pct"].configure(text=f"{nr:.0f}MB"); w["bar"].set_value(min(100,nr/10))
                w["sub"].configure(text=f"Sent:{data.get('net_sent_mb',0):.0f}MB  Recv:{nr:.0f}MB")
            if hasattr(self,"extra_lbl"):
                self.extra_lbl["processes"].configure(text=str(data.get("processes",0)))
                self.extra_lbl["boot_time"].configure(text=data.get("boot_time","--"))
                self.extra_lbl["net_speed"].configure(
                    text=f"↑{data.get('net_sent_speed',0):.1f}  ↓{data.get('net_recv_speed',0):.1f} MB/s")
        except Exception: pass

    # ══════════════════════════════════════════════════════════════════════
    # TAB: PASSWORD CHECKER
    # ══════════════════════════════════════════════════════════════════════

    def _tab_password(self,parent):
        tk.Label(parent,text="  ◈  PASSWORD STRENGTH ANALYSER",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=2).pack(fill=tk.X)
        content=tk.Frame(parent,bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH,expand=True,padx=30,pady=20)
        tk.Label(content,text="ENTER PASSWORD TO ANALYSE",font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"],fg=T["CYAN_DIM"],anchor="w").pack(fill=tk.X)
        pf=tk.Frame(content,bg=T["CYAN_DIM"],padx=1,pady=1); pf.pack(fill=tk.X,pady=(4,12))
        self.pw_var=tk.StringVar(); self.pw_var.trace("w",lambda *a:self._analyse_pw())
        self.pw_entry=tk.Entry(pf,textvariable=self.pw_var,font=("Consolas",14),
                                bg=T["BG_CARD"],fg=T["GREEN"],insertbackground=T["GREEN"],
                                relief=tk.FLAT,bd=8,show="●"); self.pw_entry.pack(fill=tk.X)
        sr=tk.Frame(content,bg=T["BG_DEEP"]); sr.pack(fill=tk.X,pady=(0,16))
        self.pw_show=tk.BooleanVar(value=False)
        tk.Checkbutton(sr,text="Show password",variable=self.pw_show,font=("Consolas",8),
                       bg=T["BG_DEEP"],fg=T["TEXT_DIM"],selectcolor=T["BG_CARD"],
                       activebackground=T["BG_DEEP"],
                       command=lambda:self.pw_entry.configure(show="" if self.pw_show.get() else "●")).pack(side=tk.LEFT)
        rc=tk.Frame(content,bg=T["BG_CARD"],padx=20,pady=16); rc.pack(fill=tk.X)
        tk.Frame(rc,bg=T["CYAN"],height=2).pack(fill=tk.X,pady=(0,12))
        self.pw_lvl=tk.Label(rc,text="STRENGTH: --",font=("Consolas",22,"bold"),bg=T["BG_CARD"],fg=T["TEXT_DIM"])
        self.pw_lvl.pack(anchor="w")
        sr2=tk.Frame(rc,bg=T["BG_CARD"]); sr2.pack(fill=tk.X,pady=(8,4))
        tk.Label(sr2,text="SCORE: ",font=("Consolas",9),bg=T["BG_CARD"],fg=T["TEXT_DIM"]).pack(side=tk.LEFT)
        self.pw_score=tk.Label(sr2,text="0/100",font=("Consolas",9,"bold"),bg=T["BG_CARD"],fg=T["TEXT_DIM"])
        self.pw_score.pack(side=tk.LEFT,padx=(0,10))
        self.pw_bar=MiniBar(sr2,width=300,height=12,bg=T["BG_CARD"]); self.pw_bar.pack(side=tk.LEFT)
        det=tk.Frame(rc,bg=T["BG_CARD"]); det.pack(fill=tk.X,pady=(12,0))
        ld=tk.Frame(det,bg=T["BG_CARD"]); ld.pack(side=tk.LEFT,fill=tk.Y,padx=(0,30))
        tk.Label(ld,text="CHECKS:",font=("Consolas",8,"bold"),bg=T["BG_CARD"],fg=T["CYAN_DIM"],anchor="w").pack(fill=tk.X)
        self.pw_checks={}
        for key,lbl in [("length_8","8+ chars"),("length_12","12+ chars"),("upper","Uppercase A-Z"),
                         ("lower","Lowercase a-z"),("digit","Numbers 0-9"),("special","Special !@#$"),
                         ("no_common","Not a common password")]:
            r2=tk.Frame(ld,bg=T["BG_CARD"]); r2.pack(fill=tk.X,pady=1)
            dot=tk.Label(r2,text="○",font=("Consolas",10),bg=T["BG_CARD"],fg=T["TEXT_DIM"]); dot.pack(side=tk.LEFT)
            tk.Label(r2,text=f" {lbl}",font=("Consolas",8),bg=T["BG_CARD"],fg=T["TEXT_DIM"]).pack(side=tk.LEFT)
            self.pw_checks[key]=dot
        rd=tk.Frame(det,bg=T["BG_CARD"]); rd.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        tk.Label(rd,text="CRACK TIME:",font=("Consolas",8,"bold"),bg=T["BG_CARD"],fg=T["CYAN_DIM"],anchor="w").pack(fill=tk.X)
        self.pw_crack=tk.Label(rd,text="--",font=("Consolas",16,"bold"),bg=T["BG_CARD"],fg=T["TEXT_DIM"])
        self.pw_crack.pack(anchor="w",pady=(2,12))
        tk.Label(rd,text="SUGGESTIONS:",font=("Consolas",8,"bold"),bg=T["BG_CARD"],fg=T["CYAN_DIM"],anchor="w").pack(fill=tk.X)
        self.pw_sugg=tk.Text(rd,height=5,font=("Segoe UI",9),bg=T["LOG_BG"],fg=T["ORANGE"],
                              relief=tk.FLAT,padx=8,pady=4,state=tk.DISABLED,wrap=tk.WORD)
        self.pw_sugg.pack(fill=tk.X)

    def _analyse_pw(self):
        pw=self.pw_var.get()
        if not pw:
            self.pw_lvl.configure(text="STRENGTH: --",fg=T["TEXT_DIM"])
            self.pw_score.configure(text="0/100",fg=T["TEXT_DIM"])
            self.pw_crack.configure(text="--",fg=T["TEXT_DIM"])
            self.pw_bar.set_value(0)
            for d in self.pw_checks.values(): d.configure(text="○",fg=T["TEXT_DIM"])
            return
        r=check_password(pw)
        self.pw_lvl.configure(text=f"STRENGTH: {r['level']}",fg=r["color"])
        self.pw_score.configure(text=f"{r['score']}/100",fg=r["color"])
        self.pw_crack.configure(text=r["crack"],fg=r["color"])
        self.pw_bar.animate_to(r["score"],r["color"])
        for key,dot in self.pw_checks.items():
            p=r["checks"].get(key,False)
            dot.configure(text="●" if p else "○",fg=T["GREEN"] if p else T["RED"])
        self.pw_sugg.configure(state=tk.NORMAL)
        self.pw_sugg.delete(1.0,tk.END)
        if r["suggestions"]:
            for s in r["suggestions"]: self.pw_sugg.insert(tk.END,f"  • {s}\n")
        else: self.pw_sugg.insert(tk.END,"  ✓ Strong password!")
        self.pw_sugg.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: FIREWALL MANAGER
    # ══════════════════════════════════════════════════════════════════════

    def _tab_firewall(self, parent):
        hdr=tk.Frame(parent,bg=T["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr,bg=T["CYAN"],height=2).pack(fill=tk.X)
        row=tk.Frame(hdr,bg=T["BG_PANEL"],pady=10,padx=14); row.pack(fill=tk.X)
        tk.Label(row,text="◈  FIREWALL RULES MANAGER",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"]).pack(side=tk.LEFT)

        # Status + controls
        status_row=tk.Frame(parent,bg=T["BG_ELEVATED"],padx=14,pady=8); status_row.pack(fill=tk.X)
        self.fw_status_var=tk.StringVar(value="Checking firewall status...")
        tk.Label(status_row,textvariable=self.fw_status_var,font=("Consolas",9),
                 bg=T["BG_ELEVATED"],fg=T["CYAN"]).pack(side=tk.LEFT)
        tk.Button(status_row,text="🔄 REFRESH",font=("Consolas",8),
                  bg=T["BG_CARD"],fg=T["CYAN"],relief=tk.FLAT,cursor="hand2",
                  padx=8,command=self._fw_refresh).pack(side=tk.RIGHT)
        tk.Button(status_row,text="✓ ENABLE ALL",font=("Consolas",8,"bold"),
                  bg=T["GREEN_DIM"],fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                  padx=8,command=lambda:self._fw_toggle("on")).pack(side=tk.RIGHT,padx=4)
        tk.Button(status_row,text="✕ DISABLE ALL",font=("Consolas",8),
                  bg="#3A0A0A",fg=T["RED"],relief=tk.FLAT,cursor="hand2",
                  padx=8,command=lambda:self._fw_toggle("off")).pack(side=tk.RIGHT,padx=4)

        # Add rule panel
        add_panel=tk.Frame(parent,bg=T["BG_CARD"],padx=14,pady=10); add_panel.pack(fill=tk.X,padx=8,pady=6)
        tk.Frame(add_panel,bg=T["CYAN"],height=1).pack(fill=tk.X,pady=(0,8))
        tk.Label(add_panel,text="ADD NEW RULE",font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"],fg=T["CYAN"],anchor="w").pack(fill=tk.X)
        fields_row=tk.Frame(add_panel,bg=T["BG_CARD"]); fields_row.pack(fill=tk.X,pady=4)

        self.fw_name=tk.StringVar(); self.fw_port=tk.StringVar()
        self.fw_proto=tk.StringVar(value="TCP"); self.fw_action=tk.StringVar(value="block")
        for label,var,w in [("Rule Name",self.fw_name,20),("Port",self.fw_port,8)]:
            tk.Label(fields_row,text=f"{label}:",font=("Consolas",8),
                     bg=T["BG_CARD"],fg=T["TEXT_DIM"]).pack(side=tk.LEFT,padx=(0,4))
            ef=tk.Frame(fields_row,bg=T["CYAN_DIM"],padx=1,pady=1); ef.pack(side=tk.LEFT,padx=(0,12))
            tk.Entry(ef,textvariable=var,font=("Consolas",10),width=w,
                     bg=T["BG_DEEP"],fg=T["GREEN"],insertbackground=T["GREEN"],
                     relief=tk.FLAT,bd=4).pack()

        for label,var,opts in [("Protocol",self.fw_proto,["TCP","UDP"]),
                                ("Action",self.fw_action,["block","allow"])]:
            tk.Label(fields_row,text=f"{label}:",font=("Consolas",8),
                     bg=T["BG_CARD"],fg=T["TEXT_DIM"]).pack(side=tk.LEFT,padx=(0,4))
            om=tk.OptionMenu(fields_row,var,*opts)
            om.configure(font=("Consolas",8),bg=T["BG_DEEP"],fg=T["CYAN"],
                          relief=tk.FLAT,highlightthickness=0,activebackground=T["BG_ELEVATED"])
            om.pack(side=tk.LEFT,padx=(0,12))

        tk.Button(fields_row,text="+ ADD RULE",font=("Consolas",9,"bold"),
                  bg=T["CYAN"],fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                  padx=10,pady=4,command=self._fw_add_rule).pack(side=tk.LEFT,padx=8)

        self.fw_msg=tk.Label(add_panel,text="",font=("Consolas",8),
                              bg=T["BG_CARD"],fg=T["GREEN"]); self.fw_msg.pack(anchor="w",pady=(4,0))

        # Rules table
        cols=("Rule Name","Direction","Protocol","Port","Action","Enabled")
        sty=ttk.Style()
        sty.configure("FW.Treeview",background=T["BG_CARD"],foreground=T["TEXT_MID"],
                       fieldbackground=T["BG_CARD"],rowheight=26,font=("Consolas",8))
        sty.configure("FW.Treeview.Heading",background=T["BG_ELEVATED"],
                       foreground=T["CYAN"],font=("Consolas",8,"bold"))
        tf=tk.Frame(parent,bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH,expand=True,padx=8,pady=4)
        self.fw_tree=ttk.Treeview(tf,columns=cols,show="headings",style="FW.Treeview")
        for col,w in zip(cols,[280,80,80,80,70,70]):
            self.fw_tree.heading(col,text=col); self.fw_tree.column(col,width=w,anchor="w")
        self.fw_tree.tag_configure("block",foreground=T["RED"])
        self.fw_tree.tag_configure("allow",foreground=T["GREEN"])
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.fw_tree.yview)
        self.fw_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.fw_tree.pack(fill=tk.BOTH,expand=True)

        # Delete button
        tk.Button(parent,text="🗑 DELETE SELECTED RULE",font=("Consolas",9),
                  bg="#3A0A0A",fg=T["RED"],relief=tk.FLAT,cursor="hand2",
                  padx=10,pady=6,command=self._fw_delete_rule).pack(pady=6)

        self.after(700, self._fw_refresh)

    def _fw_refresh(self):
        status=self.fw_manager.get_firewall_status()
        self.fw_status_var.set(
            f"Domain: {status['domain']}  |  Private: {status['private']}  |  Public: {status['public']}")
        threading.Thread(target=self._fw_load_rules,daemon=True).start()

    def _fw_load_rules(self):
        rules=self.fw_manager.get_all_rules()
        self._ui(lambda:self._fw_show_rules(rules))

    def _fw_show_rules(self,rules):
        for r in self.fw_tree.get_children(): self.fw_tree.delete(r)
        for rule in rules[:200]:
            tag="block" if rule.get("action","").lower()=="block" else "allow"
            self.fw_tree.insert("","end",values=(
                rule.get("name",""),rule.get("direction",""),rule.get("protocol",""),
                rule.get("port",""),rule.get("action",""),rule.get("enabled","")),tags=(tag,))

    def _fw_add_rule(self):
        name=self.fw_name.get().strip(); port=self.fw_port.get().strip()
        if not name or not port:
            self.fw_msg.configure(text="⚠ Rule name and port are required",fg=T["ORANGE"]); return
        action=self.fw_action.get(); proto=self.fw_proto.get()
        if action=="block":
            ok,msg=self.fw_manager.add_block_rule(name,port,proto)
        else:
            ok,msg=self.fw_manager.add_allow_rule(name,port,proto)
        self.fw_msg.configure(text=f"{'✓' if ok else '✗'} {msg}",
                               fg=T["GREEN"] if ok else T["RED"])
        if ok:
            self.fw_name.set(""); self.fw_port.set("")
            self._fw_refresh()

    def _fw_delete_rule(self):
        sel=self.fw_tree.selection()
        if not sel: messagebox.showwarning("No Selection","Select a rule first!"); return
        name=self.fw_tree.item(sel[0])["values"][0]
        if messagebox.askyesno("Delete Rule",f"Delete rule:\n'{name}'?"):
            ok,msg=self.fw_manager.delete_rule(name)
            if ok: self._fw_refresh()
            else: messagebox.showerror("Error",msg)

    def _fw_toggle(self,state):
        ok,msg=self.fw_manager.set_firewall_all(state)
        messagebox.showinfo("Firewall",msg)
        self._fw_refresh()

    # ══════════════════════════════════════════════════════════════════════
    # TAB: AUTO-FIX
    # ══════════════════════════════════════════════════════════════════════

    def _tab_autofix(self, parent):
        tk.Label(parent,text="  ◈  ONE-CLICK VULNERABILITY AUTO-FIX ENGINE",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Label(parent,text="  Automatically fix security vulnerabilities — Run as Administrator for best results",
                 font=("Segoe UI",8),bg=T["BG_PANEL"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=2).pack(fill=tk.X)

        # Quick fix buttons
        qf=tk.Frame(parent,bg=T["BG_CARD"],padx=14,pady=10); qf.pack(fill=tk.X,padx=8,pady=6)
        tk.Label(qf,text="QUICK ACTIONS:",font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"],fg=T["CYAN_DIM"],anchor="w").pack(fill=tk.X,pady=(0,8))
        btn_row=tk.Frame(qf,bg=T["BG_CARD"]); btn_row.pack(fill=tk.X)
        for text,cmd,bg,fg in [
            ("🚨 FIX ALL CRITICAL",self._fix_all_critical,T["RED"],T["BG_DEEP"]),
            ("⚠ FIX RECOMMENDED",self._fix_recommended,T["ORANGE"],T["BG_DEEP"]),
            ("🔄 UNDO LAST FIX",self._undo_last,T["BG_ELEVATED"],T["TEXT_MID"]),
        ]:
            tk.Button(btn_row,text=text,font=("Consolas",10,"bold"),
                      bg=bg,fg=fg,relief=tk.FLAT,cursor="hand2",
                      padx=14,pady=8,command=cmd).pack(side=tk.LEFT,padx=(0,8))

        # Fix catalog
        tk.Label(parent,text="  ALL AVAILABLE FIXES:",font=("Consolas",9,"bold"),
                 bg=T["BG_ELEVATED"],fg=T["CYAN"],anchor="w",pady=6,padx=14).pack(fill=tk.X)

        canvas=tk.Canvas(parent,bg=T["BG_DEEP"],highlightthickness=0)
        vsb=tk.Scrollbar(parent,orient=tk.VERTICAL,command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        canvas.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        inner=tk.Frame(canvas,bg=T["BG_DEEP"])
        cw=canvas.create_window((0,0),window=inner,anchor="nw")
        inner.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",lambda e:canvas.itemconfig(cw,width=e.width))
        canvas.bind_all("<MouseWheel>",lambda e:canvas.yview_scroll(int(-1*(e.delta/120)),"units"))

        self.fix_result_labels={}
        for fix in self.auto_fixer.get_catalog():
            sev_col=RISK_COLORS.get(fix["severity"],T["TEXT_DIM"])
            card=tk.Frame(inner,bg=T["BG_CARD"]); card.pack(fill=tk.X,padx=12,pady=4)
            row_h=tk.Frame(card,bg=T["BG_ELEVATED"]); row_h.pack(fill=tk.X)
            tk.Frame(row_h,bg=sev_col,width=4).pack(side=tk.LEFT,fill=tk.Y)
            tk.Label(row_h,text=f"  [{fix['severity']}] {fix['title']}",
                     font=("Consolas",10,"bold"),bg=T["BG_ELEVATED"],fg=sev_col,
                     pady=7,anchor="w").pack(side=tk.LEFT)
            result_lbl=tk.Label(row_h,text="",font=("Consolas",8),
                                 bg=T["BG_ELEVATED"],fg=T["GREEN"]); result_lbl.pack(side=tk.RIGHT,padx=8)
            self.fix_result_labels[fix["id"]]=result_lbl

            body=tk.Frame(card,bg=T["BG_CARD"],padx=14,pady=6); body.pack(fill=tk.X)
            tk.Label(body,text=fix["description"],font=("Segoe UI",9),
                     bg=T["BG_CARD"],fg=T["TEXT_MID"],anchor="w").pack(side=tk.LEFT,fill=tk.X,expand=True)
            btn_f=tk.Frame(body,bg=T["BG_CARD"]); btn_f.pack(side=tk.RIGHT)
            tk.Button(btn_f,text="▶ APPLY",font=("Consolas",8,"bold"),
                      bg=sev_col,fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                      padx=8,pady=3,
                      command=lambda fid=fix["id"]:self._apply_one_fix(fid)).pack(side=tk.LEFT,padx=4)
            if fix.get("reversible"):
                tk.Button(btn_f,text="↩ UNDO",font=("Consolas",8),
                          bg=T["BG_ELEVATED"],fg=T["TEXT_MID"],relief=tk.FLAT,cursor="hand2",
                          padx=8,pady=3,
                          command=lambda fid=fix["id"]:self._undo_fix(fid)).pack(side=tk.LEFT)

    def _apply_one_fix(self,fid):
        def run():
            ok,msg=self.auto_fixer.apply_fix(fid)
            def update():
                lbl=self.fix_result_labels.get(fid)
                if lbl: lbl.configure(text=f"{'✓' if ok else '✗'} {'Applied!' if ok else 'Failed'}",
                                       fg=T["GREEN"] if ok else T["RED"])
                self._log(f"[AUTO-FIX] {msg}","green" if ok else "red")
            self._ui(update)
        threading.Thread(target=run,daemon=True).start()

    def _undo_fix(self,fid):
        ok,msg=self.auto_fixer.undo_fix(fid)
        self._log(f"[UNDO] {msg}","cyan" if ok else "red")
        lbl=self.fix_result_labels.get(fid)
        if lbl: lbl.configure(text="↩ Undone" if ok else "✗ Failed",
                               fg=T["CYAN"] if ok else T["RED"])

    def _fix_all_critical(self):
        if not messagebox.askyesno("Fix Critical",
            "Apply ALL CRITICAL fixes?\nThis will block RDP, SMB, enable firewall etc.\n\nRun as Administrator recommended."):
            return
        def run():
            results=self.auto_fixer.apply_all_critical(
                progress_cb=lambda m:self._log_safe(m,"orange"))
            self._ui(lambda:self._show_fix_results(results))
        threading.Thread(target=run,daemon=True).start()

    def _fix_recommended(self):
        if not messagebox.askyesno("Fix Recommended","Apply all CRITICAL + HIGH fixes?"):
            return
        def run():
            results=self.auto_fixer.apply_recommended(
                progress_cb=lambda m:self._log_safe(m,"orange"))
            self._ui(lambda:self._show_fix_results(results))
        threading.Thread(target=run,daemon=True).start()

    def _show_fix_results(self,results):
        success=sum(1 for _,ok,_ in results if ok)
        self._log(f"[AUTO-FIX] {success}/{len(results)} fixes applied successfully","green")

    def _undo_last(self):
        log=self.auto_fixer.get_log()
        if not log: messagebox.showinfo("Nothing","No fixes applied yet."); return
        last=[e for e in log if e["success"]]
        if not last: messagebox.showinfo("Nothing","No successful fixes to undo."); return
        fid=last[-1]["id"]
        ok,msg=self.auto_fixer.undo_fix(fid)
        messagebox.showinfo("Undo",msg)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: REAL-TIME ALERTS
    # ══════════════════════════════════════════════════════════════════════

    def _tab_alerts(self, parent):
        hdr=tk.Frame(parent,bg=T["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr,bg=T["RED"],height=2).pack(fill=tk.X)
        row=tk.Frame(hdr,bg=T["BG_PANEL"],pady=10,padx=14); row.pack(fill=tk.X)
        tk.Label(row,text="◈  REAL-TIME THREAT ALERT SYSTEM",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["RED"]).pack(side=tk.LEFT)
        tk.Button(row,text="▶ MANUAL CHECK",font=("Consolas",9,"bold"),
                  bg=T["CYAN"],fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                  padx=12,pady=6,command=self.alert_system.manual_check).pack(side=tk.RIGHT)
        tk.Button(row,text="🗑 CLEAR LOG",font=("Consolas",8),
                  bg=T["BG_CARD"],fg=T["TEXT_MID"],relief=tk.FLAT,cursor="hand2",
                  padx=8,pady=6,command=self._clear_alerts).pack(side=tk.RIGHT,padx=6)

        # Toggle
        self.alert_enabled=tk.BooleanVar(value=True)
        tk.Checkbutton(row,text="  Monitoring ON",variable=self.alert_enabled,
                       font=("Consolas",9,"bold"),bg=T["BG_PANEL"],fg=T["GREEN"],
                       selectcolor=T["BG_CARD"],activebackground=T["BG_PANEL"],
                       command=lambda:setattr(self.alert_system,"enabled",self.alert_enabled.get())
                       ).pack(side=tk.RIGHT,padx=12)

        tk.Label(parent,text="  Monitors: new open ports, firewall changes, suspicious connections  |  Checks every 30 seconds",
                 font=("Segoe UI",8),bg=T["BG_ELEVATED"],fg=T["TEXT_DIM"],
                 anchor="w",padx=14,pady=6).pack(fill=tk.X)

        # Alert log table
        cols=("Time","Severity","Title","Message")
        sty=ttk.Style()
        sty.configure("A.Treeview",background=T["BG_CARD"],foreground=T["TEXT_MID"],
                       fieldbackground=T["BG_CARD"],rowheight=30,font=("Consolas",9))
        sty.configure("A.Treeview.Heading",background=T["BG_ELEVATED"],
                       foreground=T["RED"],font=("Consolas",9,"bold"))
        tf=tk.Frame(parent,bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        self.alert_tree=ttk.Treeview(tf,columns=cols,show="headings",style="A.Treeview")
        for col,w in zip(cols,[80,90,200,500]):
            self.alert_tree.heading(col,text=col); self.alert_tree.column(col,width=w,anchor="w")
        self.alert_tree.tag_configure("CRITICAL",foreground=T["RED"])
        self.alert_tree.tag_configure("HIGH",foreground=T["ORANGE"])
        self.alert_tree.tag_configure("INFO",foreground=T["GREEN"])
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.alert_tree.pack(fill=tk.BOTH,expand=True)

    def _on_alert(self, alert):
        """Called from background thread when alert fires."""
        try:
            self._ui( lambda a=alert: self._show_alert(a))
        except RuntimeError: pass

    def _show_alert(self,alert):
        # Add to table
        sev=alert["severity"]
        self.alert_tree.insert("","0",values=(
            alert["time"],sev,alert["title"],
            alert["message"].replace("\n"," ")[:80]),tags=(sev,))

        # Update badge
        count=len(self.alert_system.alert_log)
        self.alert_badge.configure(text=f"🔔 {count} ALERTS",
                                    fg=T["RED"] if count>0 else T["TEXT_DIM"])

        # Popup for CRITICAL
        if sev=="CRITICAL":
            self._show_alert_popup(alert)

    def _show_alert_popup(self,alert):
        popup=tk.Toplevel(self); popup.title("⚠ SECURITY ALERT")
        popup.geometry("420x220"); popup.configure(bg=T["BG_DEEP"])
        popup.attributes("-topmost",True)
        popup.update_idletasks()
        x=(popup.winfo_screenwidth()-420)//2; y=(popup.winfo_screenheight()-220)//2
        popup.geometry(f"+{x}+{y}")
        tk.Frame(popup,bg=T["RED"],height=4).pack(fill=tk.X)
        tk.Label(popup,text=f"⚠  {alert['title']}",font=("Consolas",13,"bold"),
                 bg=T["BG_DEEP"],fg=T["RED"],pady=12).pack()
        tk.Label(popup,text=alert["message"],font=("Segoe UI",9),
                 bg=T["BG_DEEP"],fg=T["TEXT_MID"],wraplength=380,justify=tk.LEFT).pack(padx=20)
        tk.Label(popup,text=f"Time: {alert['time']}",font=("Consolas",8),
                 bg=T["BG_DEEP"],fg=T["TEXT_DIM"]).pack(pady=8)
        tk.Button(popup,text="ACKNOWLEDGE",font=("Consolas",10,"bold"),
                  bg=T["RED"],fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                  padx=16,pady=6,command=popup.destroy).pack()
        popup.after(10000,lambda:popup.destroy() if popup.winfo_exists() else None)

    def _clear_alerts(self):
        self.alert_system.clear_log()
        for r in self.alert_tree.get_children(): self.alert_tree.delete(r)
        self.alert_badge.configure(text="🔔 0 ALERTS",fg=T["TEXT_DIM"])

    # ══════════════════════════════════════════════════════════════════════
    # TAB: SCHEDULER
    # ══════════════════════════════════════════════════════════════════════

    def _tab_schedule(self, parent):
        tk.Label(parent,text="  ◈  SCHEDULED AUTO-SCAN — DAILY / WEEKLY",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=2).pack(fill=tk.X)

        content=tk.Frame(parent,bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH,expand=True,padx=20,pady=20)

        card=tk.Frame(content,bg=T["BG_CARD"],padx=20,pady=20); card.pack(fill=tk.X)
        tk.Frame(card,bg=T["CYAN"],height=2).pack(fill=tk.X,pady=(0,14))

        cfg=self.scheduler.get_config()

        # Enable toggle
        self.sched_enabled=tk.BooleanVar(value=cfg.get("enabled",False))
        tk.Checkbutton(card,text="  ENABLE SCHEDULED SCANNING",
                       variable=self.sched_enabled,
                       font=("Consolas",10,"bold"),bg=T["BG_CARD"],fg=T["GREEN"],
                       selectcolor=T["BG_DEEP"],activebackground=T["BG_CARD"]).pack(anchor="w",pady=(0,12))

        grid=tk.Frame(card,bg=T["BG_CARD"]); grid.pack(fill=tk.X)

        self.sched_freq=tk.StringVar(value=cfg.get("frequency","daily"))
        self.sched_time=tk.StringVar(value=cfg.get("time","02:00"))
        self.sched_ip=tk.StringVar(value=cfg.get("target_ip","127.0.0.1"))

        for row_n,(label,var,widget_type,opts) in enumerate([
            ("FREQUENCY:",  self.sched_freq, "option",  ["daily","weekly"]),
            ("SCAN TIME (HH:MM):", self.sched_time,"entry",   None),
            ("TARGET IP:",  self.sched_ip,   "entry",   None),
        ]):
            tk.Label(grid,text=label,font=("Consolas",9,"bold"),
                     bg=T["BG_CARD"],fg=T["CYAN_DIM"],anchor="w",width=22).grid(
                     row=row_n,column=0,sticky="w",pady=8)
            if widget_type=="option":
                om=tk.OptionMenu(grid,var,*opts)
                om.configure(font=("Consolas",10),bg=T["BG_DEEP"],fg=T["GREEN"],
                              relief=tk.FLAT,highlightthickness=0,width=10,
                              activebackground=T["BG_ELEVATED"])
                om.grid(row=row_n,column=1,sticky="w",padx=12)
            else:
                ef=tk.Frame(grid,bg=T["CYAN_DIM"],padx=1,pady=1)
                ef.grid(row=row_n,column=1,sticky="w",padx=12)
                tk.Entry(ef,textvariable=var,font=("Consolas",11),width=16,
                         bg=T["BG_DEEP"],fg=T["GREEN"],insertbackground=T["GREEN"],
                         relief=tk.FLAT,bd=5).pack()

        tk.Button(card,text="💾 SAVE SCHEDULE",font=("Consolas",11,"bold"),
                  bg=T["CYAN"],fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                  pady=10,command=self._save_schedule).pack(fill=tk.X,pady=(16,0))

        self.sched_status=tk.StringVar(value=self.scheduler.get_status_text())
        tk.Label(content,textvariable=self.sched_status,font=("Consolas",9),
                 bg=T["BG_ELEVATED"],fg=T["CYAN"],anchor="w",padx=14,pady=8).pack(fill=tk.X,pady=(12,0))

        # History of scheduled runs
        tk.Label(content,text="SCHEDULED RUN HISTORY:",font=("Consolas",8,"bold"),
                 bg=T["BG_DEEP"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X,pady=(12,4))
        stats=self.scan_history.get_stats()
        if stats:
            tk.Label(content,text=f"  Total runs: {stats.get('run_count',0)} (across all scans)  |  Last: {stats.get('last_scan','Never')}",
                     font=("Consolas",9),bg=T["BG_CARD"],fg=T["GREEN"],
                     anchor="w",padx=14,pady=8).pack(fill=tk.X)

    def _save_schedule(self):
        self.scheduler.update(
            enabled  =self.sched_enabled.get(),
            frequency=self.sched_freq.get(),
            scan_time=self.sched_time.get(),
            target_ip=self.sched_ip.get()
        )
        self.sched_status.set(self.scheduler.get_status_text())
        messagebox.showinfo("Saved",
            f"Schedule saved!\n{'ENABLED ✓' if self.sched_enabled.get() else 'DISABLED'}\n"
            f"Next run: {self.scheduler.get_config().get('next_run','--')}")

    def _scheduled_scan(self,target_ip):
        """Called by scheduler — run auto scan."""
        try:
            self._log(f"[SCHEDULER] Auto-scan triggered for {target_ip}","cyan")
        except RuntimeError: pass
        self.ip_var.set(target_ip)
        self._ui(self._on_scan)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: HARDENING CHECKLIST
    # ══════════════════════════════════════════════════════════════════════

    def _tab_hardening(self, parent):
        tk.Label(parent,text="  ◈  SYSTEM HARDENING CHECKLIST — STEP BY STEP",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Label(parent,text="  Complete all steps to significantly improve your security posture",
                 font=("Segoe UI",8),bg=T["BG_PANEL"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=2).pack(fill=tk.X)

        canvas=tk.Canvas(parent,bg=T["BG_DEEP"],highlightthickness=0)
        vsb=tk.Scrollbar(parent,orient=tk.VERTICAL,command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        canvas.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        inner=tk.Frame(canvas,bg=T["BG_DEEP"])
        cw=canvas.create_window((0,0),window=inner,anchor="nw")
        inner.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",lambda e:canvas.itemconfig(cw,width=e.width))
        canvas.bind_all("<MouseWheel>",lambda e:canvas.yview_scroll(int(-1*(e.delta/120)),"units"))

        self.harden_checks={}

        for idx,(sev,title,cmd,desc) in enumerate(HARDENING_CHECKLIST):
            sev_col=RISK_COLORS.get(sev,T["TEXT_DIM"])
            card=tk.Frame(inner,bg=T["BG_CARD"]); card.pack(fill=tk.X,padx=12,pady=4)
            row=tk.Frame(card,bg=T["BG_CARD"],padx=12,pady=10); row.pack(fill=tk.X)

            # Checkbox
            var=tk.BooleanVar(value=False)
            cb=tk.Checkbutton(row,variable=var,bg=T["BG_CARD"],selectcolor=T["BG_DEEP"],
                               activebackground=T["BG_CARD"],
                               command=lambda v=var,c=card,s=sev_col:self._harden_check(v,c,s))
            cb.pack(side=tk.LEFT,padx=(0,8))
            self.harden_checks[idx]=var

            # Severity badge
            tk.Label(row,text=f" {sev} ",font=("Consolas",7,"bold"),
                     bg=sev_col,fg=T["BG_DEEP"],padx=4).pack(side=tk.LEFT,padx=(0,8))

            info=tk.Frame(row,bg=T["BG_CARD"]); info.pack(side=tk.LEFT,fill=tk.X,expand=True)
            tk.Label(info,text=f"Step {idx+1}: {title}",font=("Consolas",10,"bold"),
                     bg=T["BG_CARD"],fg=T["TEXT_BRIGHT"],anchor="w").pack(fill=tk.X)
            tk.Label(info,text=desc,font=("Segoe UI",8),
                     bg=T["BG_CARD"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X)

            cmd_f=tk.Frame(row,bg=T["BG_CARD"]); cmd_f.pack(side=tk.RIGHT)
            def _cp(x=cmd):
                self.clipboard_clear(); self.clipboard_append(x); self._set_status("Copied!")
            tk.Button(cmd_f,text="COPY CMD",font=("Consolas",7),
                      bg=T["BG_ELEVATED"],fg=T["CYAN"],relief=tk.FLAT,cursor="hand2",
                      padx=6,command=_cp).pack()
            tk.Label(cmd_f,text=cmd[:40]+"..." if len(cmd)>40 else cmd,
                     font=("Consolas",7),bg=T["BG_CARD"],
                     fg=T["TEXT_DIM"],anchor="e").pack()

        # Progress summary
        prog_frame=tk.Frame(inner,bg=T["BG_CARD"],padx=14,pady=10)
        prog_frame.pack(fill=tk.X,padx=12,pady=8)
        tk.Label(prog_frame,text="HARDENING PROGRESS:",font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"],fg=T["CYAN"],anchor="w").pack(fill=tk.X)
        self.harden_bar=MiniBar(prog_frame,width=400,height=16,color=T["GREEN"],bg=T["BG_CARD"])
        self.harden_bar.pack(anchor="w",pady=4)
        self.harden_pct=tk.Label(prog_frame,text="0 / 12 completed",
                                  font=("Consolas",9),bg=T["BG_CARD"],fg=T["TEXT_DIM"])
        self.harden_pct.pack(anchor="w")

    def _harden_check(self,var,card,color):
        checked=sum(1 for v in self.harden_checks.values() if v.get())
        total=len(self.harden_checks)
        pct=checked/total*100
        self.harden_bar.set_value(pct,T["GREEN"] if pct>75 else T["ORANGE"] if pct>40 else T["RED"])
        self.harden_pct.configure(text=f"{checked} / {total} completed  ({pct:.0f}%)")

    # ══════════════════════════════════════════════════════════════════════
    # TAB: THREAT MAP
    # ══════════════════════════════════════════════════════════════════════

    def _tab_threatmap(self, parent):
        tk.Label(parent,text="  ◈  GLOBAL THREAT ORIGINS MAP",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Label(parent,text="  Known cyber threat actors and their geographic origins",
                 font=("Segoe UI",8),bg=T["BG_PANEL"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=2).pack(fill=tk.X)

        canvas=tk.Canvas(parent,bg="#020D18",highlightthickness=0)
        canvas.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)

        def draw_map(event=None):
            canvas.delete("all")
            W=canvas.winfo_width(); H=canvas.winfo_height()
            if W<10 or H<10: return

            # Draw world map background (simplified continents as rectangles)
            canvas.create_rectangle(0,0,W,H,fill="#020D18",outline="")

            # Grid lines
            for x in range(0,W,W//12):
                canvas.create_line(x,0,x,H,fill="#0A1A2A",width=1)
            for y in range(0,H,H//6):
                canvas.create_line(0,y,W,y,fill="#0A1A2A",width=1)

            # Continent outlines (simplified polygons lat/lon to x/y)
            def latlon_to_xy(lat,lon):
                x=int((lon+180)/360*W)
                y=int((90-lat)/180*H)
                return x,y

            # Draw simplified continent shapes
            continents=[
                # North America
                [(60,-140),(70,-100),(60,-80),(50,-55),(25,-80),(20,-100),(30,-120),(50,-130),(60,-140)],
                # South America
                [(10,-80),(12,-70),(0,-50),(-10,-35),(-55,-70),(-40,-75),(-20,-80),(0,-80),(10,-80)],
                # Europe
                [(70,30),(60,40),(45,40),(36,36),(36,6),(44,-10),(60,0),(65,14),(70,30)],
                # Africa
                [(37,10),(37,42),(10,50),(-35,20),(-35,18),(0,-18),(15,-17),(37,10)],
                # Asia
                [(70,30),(70,140),(60,140),(40,130),(10,100),(0,100),(20,60),(30,48),(45,40),(70,30)],
                # Australia
                [(-10,130),(-10,150),(-40,150),(-40,115),(-20,115),(-10,130)],
            ]
            for continent in continents:
                points=[]
                for lat,lon in continent:
                    x,y=latlon_to_xy(lat,lon); points.extend([x,y])
                if len(points)>=4:
                    canvas.create_polygon(points,fill="#0A2A1A",outline="#0F3D28",width=1)

            # Draw threat locations
            for lat,lon,location,group,color in THREAT_LOCATIONS:
                x,y=latlon_to_xy(lat,lon)

                # Pulsing circles
                for r,alpha in [(20,"#1A0A0A"),(14,"#2A0A0A"),(8,color)]:
                    canvas.create_oval(x-r,y-r,x+r,y+r,fill=alpha,outline=color,width=1)

                # Center dot
                canvas.create_oval(x-4,y-4,x+4,y+4,fill=color,outline="white",width=1)

                # Label
                canvas.create_text(x,y-26,text=location,
                                    font=("Consolas",7,"bold"),fill=color,
                                    anchor="center")
                canvas.create_text(x,y+26,text=group[:25],
                                    font=("Consolas",6),fill=T["TEXT_DIM"],
                                    anchor="center")

            # Your location (Pakistan)
            mx,my=latlon_to_xy(30,70)
            canvas.create_oval(mx-8,my-8,mx+8,my+8,fill=T["GREEN"],outline="white",width=2)
            canvas.create_text(mx,my-20,text="📍 YOU",
                                font=("Consolas",8,"bold"),fill=T["GREEN"])

            # Legend
            canvas.create_rectangle(10,10,220,120,fill="#0A1628",outline=T["CYAN_DIM"])
            canvas.create_text(20,24,text="CYBER THREAT ORIGINS",
                                font=("Consolas",8,"bold"),fill=T["CYAN"],anchor="w")
            for i,(sev,color2,label) in enumerate([
                ("CRITICAL",T["RED"],"State-sponsored APT"),
                ("HIGH",T["ORANGE"],"Organized cybercrime"),
                ("MEDIUM",T["YELLOW"],"Hacktivist groups"),
                ("INFO",T["GREEN"],"Your location"),
            ]):
                y2=44+i*18
                canvas.create_oval(20,y2-5,30,y2+5,fill=color2,outline="")
                canvas.create_text(38,y2,text=label,
                                    font=("Consolas",7),fill=T["TEXT_MID"],anchor="w")

            canvas.create_text(W-10,H-10,
                                text=f"Active threats detected: {len(THREAT_LOCATIONS)} known APT locations",
                                font=("Consolas",7),fill=T["TEXT_DIM"],anchor="se")

        canvas.bind("<Configure>",draw_map)
        canvas.after(100,draw_map)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: SECURITY LAB
    # ══════════════════════════════════════════════════════════════════════

    def _tab_seclab(self,parent):
        sty=ttk.Style()
        sty.configure("Lab.TNotebook",background=T["BG_DEEP"],borderwidth=0)
        sty.configure("Lab.TNotebook.Tab",background=T["BG_PANEL"],
                       foreground=T["TEXT_DIM"],padding=[12,7],font=("Consolas",9))
        sty.map("Lab.TNotebook.Tab",background=[("selected",T["BG_CARD"])],
                foreground=[("selected",T["CYAN"])])
        sub=ttk.Notebook(parent,style="Lab.TNotebook"); sub.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
        f1=tk.Frame(sub,bg=T["BG_DEEP"]); sub.add(f1,text="  ⚔ ATTACKS  ")
        f2=tk.Frame(sub,bg=T["BG_DEEP"]); sub.add(f2,text="  ◉ CMD  ")
        f3=tk.Frame(sub,bg=T["BG_DEEP"]); sub.add(f3,text="  ▲ CVEs  ")
        self._seclab_attacks(f1); self._seclab_cmd(f2); self._seclab_cve(f3)

    def _scrollable(self,parent):
        canvas=tk.Canvas(parent,bg=T["BG_DEEP"],highlightthickness=0)
        vsb=tk.Scrollbar(parent,orient=tk.VERTICAL,command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        canvas.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        inner=tk.Frame(canvas,bg=T["BG_DEEP"])
        cw=canvas.create_window((0,0),window=inner,anchor="nw")
        inner.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",lambda e:canvas.itemconfig(cw,width=e.width))
        canvas.bind_all("<MouseWheel>",lambda e:canvas.yview_scroll(int(-1*(e.delta/120)),"units"))
        return inner

    def _seclab_attacks(self,parent):
        tk.Label(parent,text="  ⚔  ATTACK DIAGRAMS",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=1).pack(fill=tk.X)
        inner=self._scrollable(parent)
        for atk in ATTACKS:
            c=atk["color"]
            card=tk.Frame(inner,bg=T["BG_CARD"]); card.pack(fill=tk.X,padx=12,pady=7)
            tb=tk.Frame(card,bg=T["BG_ELEVATED"]); tb.pack(fill=tk.X)
            tk.Frame(tb,bg=c,width=4).pack(side=tk.LEFT,fill=tk.Y)
            tk.Label(tb,text=f"  {atk['title']}",font=("Consolas",11,"bold"),
                     bg=T["BG_ELEVATED"],fg=c,pady=7,anchor="w").pack(side=tk.LEFT)
            body=tk.Frame(card,bg=T["BG_CARD"],padx=14,pady=10); body.pack(fill=tk.X)
            df=tk.Frame(body,bg=T["LOG_BG"]); df.pack(fill=tk.X,pady=(3,10))
            tk.Label(df,text=atk["diagram"],font=("Consolas",9),
                     bg=T["LOG_BG"],fg="#4DCCEE",justify=tk.LEFT,anchor="w",padx=14).pack(fill=tk.X)
            tk.Label(body,text=atk["what"],font=("Segoe UI",9),
                     bg=T["BG_CARD"],fg=T["TEXT_MID"],wraplength=1100,justify=tk.LEFT,anchor="w").pack(fill=tk.X,pady=(0,6))
            tk.Label(body,text=f"⚠ {atk['risk']}",font=("Segoe UI",9),
                     bg=T["BG_CARD"],fg=T["ORANGE"],wraplength=1100,justify=tk.LEFT,anchor="w").pack(fill=tk.X,pady=(0,8))
            pf=tk.Frame(body,bg=T["LOG_BG"]); pf.pack(fill=tk.X)
            for cmd in atk["protect"]:
                r2=tk.Frame(pf,bg=T["LOG_BG"]); r2.pack(fill=tk.X,pady=1)
                tk.Label(r2,text=f"  C:\\> {cmd}",font=("Consolas",8),
                         bg=T["LOG_BG"],fg=T["GREEN"],anchor="w").pack(side=tk.LEFT,fill=tk.X,expand=True)
                def _cp(x=cmd): self.clipboard_clear(); self.clipboard_append(x)
                tk.Button(r2,text="COPY",font=("Consolas",7),bg=T["BG_ELEVATED"],
                          fg=T["GREEN"],relief=tk.FLAT,cursor="hand2",padx=6,
                          command=_cp).pack(side=tk.RIGHT,padx=4)

    def _seclab_cmd(self,parent):
        tk.Label(parent,text="  ◉  CMD SECURITY COMMANDS",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=1).pack(fill=tk.X)
        inner=self._scrollable(parent)
        sections=[
            ("🌐 NETWORK","#003366",[("netstat -ano","All open ports"),("ipconfig /all","Network info"),
              ("arp -a","Network devices"),("ping [IP]","Test connectivity")]),
            ("🔥 FIREWALL","#330000",[("netsh advfirewall show allprofiles","Firewall status"),
              ("netsh advfirewall set allprofiles state on","Enable firewall"),
              ("netsh advfirewall reset","Reset firewall")]),
            ("🔐 PASSWORDS","#330033",[("net accounts","Password policy"),
              ("net accounts /lockoutthreshold:5","Set lockout"),
              ("net accounts /minpwlen:12","Min password length")]),
            ("🔄 UPDATES","#002200",[("wuauclt /detectnow","Check updates"),
              ("wuauclt /updatenow","Install updates"),("wmic qfe list","View patches")]),
        ]
        for sec_title,sec_color,cmds in sections:
            sf=tk.Frame(inner,bg=T["BG_CARD"]); sf.pack(fill=tk.X,padx=12,pady=6)
            th=tk.Frame(sf,bg=sec_color); th.pack(fill=tk.X)
            tk.Frame(th,bg=T["CYAN"],width=3).pack(side=tk.LEFT,fill=tk.Y)
            tk.Label(th,text=f"  {sec_title}",font=("Consolas",10,"bold"),
                     bg=sec_color,fg=T["CYAN"],pady=7).pack(side=tk.LEFT)
            for cmd,desc in cmds:
                r2=tk.Frame(sf,bg=T["LOG_BG"]); r2.pack(fill=tk.X,pady=1)
                tk.Label(r2,text=f"  > {cmd}",font=("Consolas",8),
                         bg=T["LOG_BG"],fg=T["GREEN"],anchor="w",width=50).pack(side=tk.LEFT,padx=(4,0))
                tk.Label(r2,text=f"  ← {desc}",font=("Segoe UI",8),
                         bg=T["LOG_BG"],fg=T["TEXT_DIM"],anchor="w").pack(side=tk.LEFT,fill=tk.X,expand=True)
                def _cp(x=cmd): self.clipboard_clear(); self.clipboard_append(x)
                tk.Button(r2,text="COPY",font=("Consolas",7),bg=T["BG_ELEVATED"],
                          fg=T["CYAN"],relief=tk.FLAT,cursor="hand2",padx=6,
                          command=_cp).pack(side=tk.RIGHT,padx=4,pady=1)

    def _seclab_cve(self,parent):
        tk.Label(parent,text="  ▲  CVE DATABASE — REAL VULNERABILITIES",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg=T["CYAN"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg=T["CYAN"],height=1).pack(fill=tk.X)
        inner=self._scrollable(parent)
        cves=[
            ("CVE-2017-0144","EternalBlue / WannaCry","CRITICAL",
             "Windows SMB port 445 — infected 200,000+ systems worldwide. $4B damage. NSA-developed exploit."),
            ("CVE-2019-0708","BlueKeep — No-Auth RDP RCE","CRITICAL",
             "Full system control without any password via RDP. 1M+ systems exposed."),
            ("CVE-2021-34527","PrintNightmare","CRITICAL",
             "Normal users could gain SYSTEM privileges via Print Spooler."),
            ("CVE-2021-44228","Log4Shell — Log4j","CRITICAL",
             "One string = remote code execution. Billions of servers affected. CVSS: 10.0"),
            ("CVE-2022-30190","Follina — MSDT","HIGH",
             "Open Word doc (no macros) = code execution. Zero-day before patch."),
        ]
        for cve_id,name,sev,desc in cves:
            sc=RISK_COLORS.get(sev,T["RED"])
            card=tk.Frame(inner,bg=T["BG_CARD"]); card.pack(fill=tk.X,padx=12,pady=6)
            hdr2=tk.Frame(card,bg=T["BG_ELEVATED"]); hdr2.pack(fill=tk.X)
            tk.Frame(hdr2,bg=sc,width=4).pack(side=tk.LEFT,fill=tk.Y)
            tk.Label(hdr2,text=f"  {cve_id}  —  {name}",font=("Consolas",10,"bold"),
                     bg=T["BG_ELEVATED"],fg=sc,pady=7).pack(side=tk.LEFT)
            tk.Label(hdr2,text=f"  ● {sev}  ",font=("Consolas",9,"bold"),
                     bg=sc,fg=T["BG_DEEP"],pady=7).pack(side=tk.RIGHT)
            body=tk.Frame(card,bg=T["BG_CARD"],padx=14,pady=8); body.pack(fill=tk.X)
            tk.Label(body,text=desc,font=("Segoe UI",9),bg=T["BG_CARD"],
                     fg=T["TEXT_MID"],wraplength=1100,justify=tk.LEFT,anchor="w").pack(fill=tk.X)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: HISTORY
    # ══════════════════════════════════════════════════════════════════════

    def _tab_history(self,parent):
        hdr=tk.Frame(parent,bg=T["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr,bg=T["CYAN"],height=2).pack(fill=tk.X)
        row=tk.Frame(hdr,bg=T["BG_PANEL"],pady=10,padx=14); row.pack(fill=tk.X)
        tk.Label(row,text="◈  SCAN HISTORY",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg=T["CYAN"]).pack(side=tk.LEFT)
        tk.Button(row,text="🗑 CLEAR",font=("Consolas",8),bg=T["BG_CARD"],fg=T["RED"],
                  relief=tk.FLAT,cursor="hand2",padx=8,
                  command=self._clear_history).pack(side=tk.RIGHT)
        tk.Button(row,text="⟳ REFRESH",font=("Consolas",8),bg=T["BG_CARD"],fg=T["CYAN"],
                  relief=tk.FLAT,cursor="hand2",padx=8,
                  command=self._load_history).pack(side=tk.RIGHT,padx=6)
        self.hist_stats=tk.StringVar(value="No scans yet")
        tk.Label(parent,textvariable=self.hist_stats,font=("Consolas",9),
                 bg=T["BG_ELEVATED"],fg=T["CYAN"],anchor="w",padx=14,pady=6).pack(fill=tk.X)
        cols=("#","Time","Target","Level","Score","Ports","Firewall","Antivirus")
        sty=ttk.Style()
        sty.configure("H.Treeview",background=T["BG_CARD"],foreground=T["TEXT_MID"],
                       fieldbackground=T["BG_CARD"],rowheight=26,font=("Consolas",9))
        sty.configure("H.Treeview.Heading",background=T["BG_ELEVATED"],
                       foreground=T["CYAN"],font=("Consolas",9,"bold"))
        tf=tk.Frame(parent,bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        self.hist_tree=ttk.Treeview(tf,columns=cols,show="headings",style="H.Treeview")
        for col,w in zip(cols,[40,150,120,100,70,80,100,100]):
            self.hist_tree.heading(col,text=col); self.hist_tree.column(col,width=w,anchor="center")
        for tag,fg in [("CRITICAL",T["RED"]),("HIGH",T["ORANGE"]),("MEDIUM",T["YELLOW"]),("LOW",T["GREEN"])]:
            self.hist_tree.tag_configure(tag,foreground=fg)
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.hist_tree.yview)
        self.hist_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.hist_tree.pack(fill=tk.BOTH,expand=True)
        self._load_history()

    def _load_history(self):
        for r in self.hist_tree.get_children(): self.hist_tree.delete(r)
        for e in self.scan_history.get_all():
            self.hist_tree.insert("","end",values=(
                e.get("id",""),e.get("timestamp",""),e.get("target_ip",""),
                e.get("risk_level",""),e.get("risk_score",""),
                str(len(e.get("open_ports",[]))),e.get("firewall",""),e.get("antivirus","")),
                tags=(e.get("risk_level","LOW"),))
        stats=self.scan_history.get_stats()
        if stats:
            self.hist_stats.set(f"Total: {stats['total_scans']}  ●  Avg: {stats['avg_score']}  ●  Critical: {stats['critical_count']}  ●  Last: {stats['last_scan']}")

    def _clear_history(self):
        if messagebox.askyesno("Clear","Delete all history?"):
            self.scan_history.clear(); self._load_history()
            self.hist_stats.set("History cleared.")


    # ══════════════════════════════════════════════════════════════════════
    # TAB: CTF CHALLENGES
    # ══════════════════════════════════════════════════════════════════════

    def _tab_ctf(self, parent):
        from ctf_challenges import get_all_challenges, check_answer, get_total_points
        # inline fallbacks for extended functions
        def get_rank(pts):
            if pts>=500: return ("ELITE HACKER", "#FF2D55")
            if pts>=300: return ("EXPERT",       "#FF8C42")
            if pts>=150: return ("INTERMEDIATE", "#FFD60A")
            if pts>=50:  return ("BEGINNER",     "#00D4FF")
            return ("NOVICE", "#7BAFD4")
        def get_solved_count(): return len(self._ctf_solved)
        def reset_progress():
            self._ctf_solved = set()
            self._ctf_score  = 0

        tk.Label(parent,text="  ◈  CTF SECURITY CHALLENGES — CAPTURE THE FLAG",
                 font=("Consolas",11,"bold"),bg=T["BG_PANEL"],fg="#FFD60A",
                 anchor="w",pady=10).pack(fill=tk.X)
        tk.Label(parent,text="  Security puzzles solve karo — points kamao — rank haasil karo!",
                 font=("Segoe UI",8),bg=T["BG_PANEL"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X)
        tk.Frame(parent,bg="#FFD60A",height=2).pack(fill=tk.X)

        self.ctf_score_var=tk.StringVar(value="Score: 0 pts  |  Solved: 0/14  |  Rank: 👾 NOVICE")
        score_bar=tk.Label(parent,textvariable=self.ctf_score_var,
                            font=("Consolas",10,"bold"),bg=T["BG_ELEVATED"],
                            fg="#FFD60A",anchor="w",padx=14,pady=8)
        score_bar.pack(fill=tk.X)

        def refresh_score():
            pts=get_total_points(); solved=get_solved_count()
            rank_title,rank_color=get_rank(pts)
            self.ctf_score_var.set(f"Score: {pts} pts  |  Solved: {solved}/14  |  Rank: {rank_title}")
            score_bar.configure(fg=rank_color)

        paned=tk.PanedWindow(parent,orient=tk.HORIZONTAL,bg=T["BG_DEEP"],sashwidth=4)
        paned.pack(fill=tk.BOTH,expand=True)
        left=tk.Frame(paned,bg=T["BG_PANEL"]); paned.add(left,minsize=280)

        hdr=tk.Frame(left,bg=T["BG_ELEVATED"],padx=10,pady=6); hdr.pack(fill=tk.X)
        tk.Label(hdr,text="CHALLENGES",font=("Consolas",9,"bold"),
                 bg=T["BG_ELEVATED"],fg="#FFD60A").pack(side=tk.LEFT)
        tk.Button(hdr,text="RESET",font=("Consolas",7),bg=T["BG_CARD"],
                  fg=T["TEXT_DIM"],relief=tk.FLAT,cursor="hand2",padx=6,
                  command=lambda:[reset_progress(),refresh_score()]).pack(side=tk.RIGHT)

        sty=ttk.Style()
        sty.configure("CTF.Treeview",background=T["BG_CARD"],foreground=T["TEXT_MID"],
                       fieldbackground=T["BG_CARD"],rowheight=28,font=("Consolas",8))
        sty.configure("CTF.Treeview.Heading",background=T["BG_ELEVATED"],
                       foreground="#FFD60A",font=("Consolas",8,"bold"))
        cols=("","Title","Pts","Diff")
        self.ctf_tree=ttk.Treeview(left,columns=cols,show="headings",style="CTF.Treeview")
        for col,w in zip(cols,[22,180,45,90]):
            self.ctf_tree.heading(col,text=col); self.ctf_tree.column(col,width=w,anchor="w")
        self.ctf_tree.tag_configure("solved", foreground=T["GREEN"])
        self.ctf_tree.tag_configure("unsolved",foreground=T["TEXT_MID"])
        vsb=ttk.Scrollbar(left,orient=tk.VERTICAL,command=self.ctf_tree.yview)
        self.ctf_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.ctf_tree.pack(fill=tk.BOTH,expand=True)

        diff_colors={"BEGINNER":"#00FF88","INTERMEDIATE":"#00D4FF","ADVANCED":"#FF8C42","EXPERT":"#FF2D55"}
        for ch in get_all_challenges():
            self.ctf_tree.insert("","end",
                values=("✓" if ch["id"] in self._ctf_solved else " ",ch["title"][:22],ch["points"],ch["difficulty"]),
                tags=("solved" if ch["id"] in self._ctf_solved else "unsolved",),iid=ch["id"])

        right=tk.Frame(paned,bg=T["BG_DEEP"]); paned.add(right,minsize=500)
        detail=tk.Frame(right,bg=T["BG_CARD"],padx=16,pady=12); detail.pack(fill=tk.X,padx=8,pady=8)
        self.ctf_title_lbl=tk.Label(detail,text="← Select a challenge",
                                     font=("Consolas",14,"bold"),bg=T["BG_CARD"],fg="#FFD60A",anchor="w")
        self.ctf_title_lbl.pack(fill=tk.X)
        meta_row=tk.Frame(detail,bg=T["BG_CARD"]); meta_row.pack(fill=tk.X,pady=4)
        self.ctf_cat_lbl=tk.Label(meta_row,text="",font=("Consolas",8),
                                   bg=T["BG_CARD"],fg=T["TEXT_DIM"]); self.ctf_cat_lbl.pack(side=tk.LEFT)
        self.ctf_pts_lbl=tk.Label(meta_row,text="",font=("Consolas",8,"bold"),
                                   bg=T["BG_CARD"],fg="#FFD60A"); self.ctf_pts_lbl.pack(side=tk.RIGHT)
        self.ctf_desc_lbl=tk.Label(detail,text="",font=("Consolas",9),
                                    bg=T["LOG_BG"],fg=T["GREEN"],
                                    justify=tk.LEFT,anchor="w",padx=12,pady=10,wraplength=520)
        self.ctf_desc_lbl.pack(fill=tk.X,pady=8)

        ans_row=tk.Frame(right,bg=T["BG_DEEP"],padx=8); ans_row.pack(fill=tk.X)
        tk.Label(ans_row,text="YOUR ANSWER:",font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"],fg=T["CYAN_DIM"]).pack(anchor="w",pady=(4,2))
        entry_row=tk.Frame(ans_row,bg=T["BG_DEEP"]); entry_row.pack(fill=tk.X)
        self.ctf_ans_var=tk.StringVar()
        af=tk.Frame(entry_row,bg=T["CYAN_DIM"],padx=1,pady=1); af.pack(side=tk.LEFT,fill=tk.X,expand=True)
        self.ctf_entry=tk.Entry(af,textvariable=self.ctf_ans_var,font=("Consolas",12),
                                 bg=T["BG_DEEP"],fg=T["GREEN"],insertbackground=T["GREEN"],
                                 relief=tk.FLAT,bd=6)
        self.ctf_entry.pack(fill=tk.X)
        self.ctf_entry.bind("<Return>",lambda e:submit_answer())
        tk.Button(entry_row,text="▶  SUBMIT",font=("Consolas",10,"bold"),bg="#FFD60A",
                  fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",padx=14,pady=6,
                  command=lambda:submit_answer()).pack(side=tk.LEFT,padx=8)

        self.ctf_result_lbl=tk.Label(right,text="",font=("Consolas",10,"bold"),
                                      bg=T["BG_DEEP"],fg=T["TEXT_DIM"],anchor="w",padx=14,pady=6)
        self.ctf_result_lbl.pack(fill=tk.X)
        self.ctf_explain=tk.Text(right,font=("Consolas",9),bg=T["LOG_BG"],
                                  fg=T["CYAN"],relief=tk.FLAT,padx=12,pady=8,
                                  height=5,wrap=tk.WORD,state=tk.DISABLED)
        self.ctf_explain.pack(fill=tk.X,padx=8,pady=(0,6))
        self._ctf_current_id=None

        def on_select(event):
            sel=self.ctf_tree.selection()
            if not sel: return
            cid=sel[0]
            ch=next((c for c in get_all_challenges() if c["id"]==cid),None)
            if not ch: return
            self._ctf_current_id=cid; self.ctf_ans_var.set("")
            diff_col=diff_colors.get(ch["difficulty"],T["TEXT_DIM"])
            self.ctf_title_lbl.configure(text=ch["title"],fg=ch["color"])
            self.ctf_cat_lbl.configure(text=f"{ch['category']}  |  {ch['difficulty']}",fg=diff_col)
            self.ctf_pts_lbl.configure(text=f"{ch['points']} pts {'✓ SOLVED' if ch['solved'] else ''}")
            self.ctf_desc_lbl.configure(text=ch["description"])
            self.ctf_result_lbl.configure(text="✓ Already solved!" if ch["id"] in self._ctf_solved else "",
                                           fg=T["GREEN"] if ch["id"] in self._ctf_solved else T["TEXT_DIM"])
            self.ctf_explain.configure(state=tk.NORMAL); self.ctf_explain.delete(1.0,tk.END)
            if ch["id"] in self._ctf_solved: self.ctf_explain.insert(tk.END,ch["explanation"])
            self.ctf_explain.configure(state=tk.DISABLED)
            self.ctf_entry.focus_set()

        def submit_answer():
            if not self._ctf_current_id: return
            ans=self.ctf_ans_var.get()
            if not ans.strip(): return
            result=check_answer(self._ctf_current_id,ans)
            if result["correct"]:
                self.ctf_result_lbl.configure(text=result["message"],fg=T["GREEN"])
                self.ctf_explain.configure(state=tk.NORMAL); self.ctf_explain.delete(1.0,tk.END)
                self.ctf_explain.insert(tk.END,result["explanation"]); self.ctf_explain.configure(state=tk.DISABLED)
                vals=self.ctf_tree.item(self._ctf_current_id)["values"]
                self.ctf_tree.item(self._ctf_current_id,tags=("solved",),
                                   values=("✓",vals[1],vals[2],vals[3]))
                self._ctf_score+=result["points_earned"]; self._ctf_solved.add(self._ctf_current_id)
                refresh_score()
            else:
                self.ctf_result_lbl.configure(text=result["message"],fg=T["RED"])
                self.ctf_explain.configure(state=tk.NORMAL); self.ctf_explain.delete(1.0,tk.END)
                self.ctf_explain.configure(state=tk.DISABLED)

        self.ctf_tree.bind("<<TreeviewSelect>>",on_select)

    # ══════════════════════════════════════════════════════════════════════
    # TAB STUBS — new modules (wifi, malware, usb, report card, attack sim, breach, news)
    # ══════════════════════════════════════════════════════════════════════

    def _tab_wifi(self,parent):
        tk.Label(parent,text="  ◈  WIFI SCANNER",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg="#00AAFF",anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg="#00AAFF",height=2).pack(fill=tk.X)
        ctrl=tk.Frame(parent,bg=T["BG_CARD"],padx=14,pady=8); ctrl.pack(fill=tk.X)
        self.btn_wifi=tk.Button(ctrl,text="📡  SCAN WIFI",font=("Consolas",10,"bold"),
                                 bg="#00AAFF",fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                                 padx=14,pady=6,command=self._on_wifi_scan); self.btn_wifi.pack(side=tk.LEFT)
        self.wifi_status=tk.Label(ctrl,text="Click to scan nearby WiFi",
                                   font=("Consolas",9),bg=T["BG_CARD"],fg=T["TEXT_DIM"])
        self.wifi_status.pack(side=tk.LEFT,padx=14)
        sty2=ttk.Style()
        sty2.configure("W.Horizontal.TProgressbar",troughcolor=T["BG_CARD"],background="#00AAFF",thickness=3)
        self.wifi_prog=ttk.Progressbar(ctrl,mode="indeterminate",length=120,style="W.Horizontal.TProgressbar")
        self.wifi_prog.pack(side=tk.RIGHT,padx=8)
        self.wifi_adapter_var=tk.StringVar(value="Adapter info loading...")
        tk.Label(parent,textvariable=self.wifi_adapter_var,font=("Consolas",8),
                 bg=T["BG_ELEVATED"],fg=T["CYAN"],anchor="w",padx=14,pady=5).pack(fill=tk.X)
        cols=("SSID","Security","Rating","Signal","Channel","BSSID","Warnings")
        sty3=ttk.Style()
        sty3.configure("W.Treeview",background=T["BG_CARD"],foreground=T["TEXT_MID"],
                        fieldbackground=T["BG_CARD"],rowheight=28,font=("Consolas",9))
        sty3.configure("W.Treeview.Heading",background=T["BG_ELEVATED"],foreground="#00AAFF",font=("Consolas",9,"bold"))
        tf=tk.Frame(parent,bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        self.wifi_tree=ttk.Treeview(tf,columns=cols,show="headings",style="W.Treeview")
        for col,w in zip(cols,[180,90,80,70,70,140,280]):
            self.wifi_tree.heading(col,text=col); self.wifi_tree.column(col,width=w,anchor="w")
        for tag,fg in [("CRITICAL",T["RED"]),("WEAK",T["ORANGE"]),("GOOD",T["CYAN"]),("SECURE",T["GREEN"])]:
            self.wifi_tree.tag_configure(tag,foreground=fg)
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.wifi_tree.yview)
        self.wifi_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.wifi_tree.pack(fill=tk.BOTH,expand=True)

    def _on_wifi_scan(self):
        self.btn_wifi.configure(state=tk.DISABLED,text="◉ SCANNING...")
        self.wifi_prog.start(10); self.wifi_status.configure(text="Scanning...")
        threading.Thread(target=self._wifi_bg,daemon=True).start()
    def _wifi_bg(self):
        try:
            result = full_wifi_scan()
            nets   = result.get("networks", [])
            total  = result.get("total", 0)
            crit   = result.get("critical_count", 0)
            self._ui( lambda: self.wifi_adapter_var.set(
                f"Networks found: {total}  |  Critical: {crit}  |  Scan: {result.get('scan_time','')}"))
            self._ui( lambda: self._show_wifi(nets))
        except Exception as e:
            self._ui( lambda: self.wifi_status.configure(text=f"Error: {e}"))
        finally:
            self._ui( self._wifi_done)
    def _wifi_done(self):
        self.wifi_prog.stop(); self.btn_wifi.configure(state=tk.NORMAL,text="📡  SCAN WIFI")
    def _show_wifi(self, networks):
        for r in self.wifi_tree.get_children(): self.wifi_tree.delete(r)
        for n in networks:
            risks = " | ".join(n.get("risks",[])) if n.get("risks") else "None"
            rating = n.get("security","UNKNOWN")
            self.wifi_tree.insert("","end", values=(
                n.get("ssid","?"), n.get("auth","?"), rating,
                n.get("signal","--"), n.get("channel","--"),
                n.get("bssid","--"), risks[:80]), tags=(rating,))
        self.wifi_status.configure(text=f"✓ {len(networks)} networks found")

    def _tab_malware(self,parent):
        tk.Label(parent,text="  ◈  MALWARE FILE SCANNER",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg="#FF8C42",anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg="#FF8C42",height=2).pack(fill=tk.X)
        ctrl=tk.Frame(parent,bg=T["BG_CARD"],padx=14,pady=10); ctrl.pack(fill=tk.X)
        self.mal_path=tk.StringVar(value=os.path.expanduser("~"))
        pf=tk.Frame(ctrl,bg=T["CYAN_DIM"],padx=1,pady=1); pf.pack(side=tk.LEFT,fill=tk.X,expand=True)
        tk.Entry(pf,textvariable=self.mal_path,font=("Consolas",10),bg=T["BG_DEEP"],
                 fg=T["GREEN"],insertbackground=T["GREEN"],relief=tk.FLAT,bd=5).pack(fill=tk.X)
        tk.Button(ctrl,text="📂",font=("Consolas",8),bg=T["BG_ELEVATED"],fg=T["CYAN"],
                  relief=tk.FLAT,cursor="hand2",padx=8,
                  command=lambda:self.mal_path.set(filedialog.askdirectory() or self.mal_path.get())).pack(side=tk.LEFT,padx=4)
        self.btn_mal=tk.Button(ctrl,text="🔍 SCAN",font=("Consolas",10,"bold"),
                                bg="#FF8C42",fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                                padx=12,pady=6,command=self._on_mal_scan); self.btn_mal.pack(side=tk.LEFT,padx=6)
        tk.Button(ctrl,text="■ STOP",font=("Consolas",8),bg=T["BG_CARD"],fg=T["TEXT_DIM"],
                  relief=tk.FLAT,cursor="hand2",padx=6,command=self._stop_mal_scan).pack(side=tk.LEFT)
        self.mal_stats_var=tk.StringVar(value="Select folder and click SCAN")
        tk.Label(parent,textvariable=self.mal_stats_var,font=("Consolas",9),
                 bg=T["BG_ELEVATED"],fg="#FF8C42",anchor="w",padx=14,pady=5).pack(fill=tk.X)
        sty=ttk.Style()
        sty.configure("Mal.Horizontal.TProgressbar",troughcolor=T["BG_CARD"],background="#FF8C42",thickness=4)
        self.mal_prog=ttk.Progressbar(parent,mode="indeterminate",style="Mal.Horizontal.TProgressbar")
        self.mal_prog.pack(fill=tk.X,padx=8)
        cols=("File","Ext","Size KB","Severity","Finding","Path")
        sty2=ttk.Style(); sty2.configure("Mal.Treeview",background=T["BG_CARD"],foreground=T["TEXT_MID"],
            fieldbackground=T["BG_CARD"],rowheight=26,font=("Consolas",8))
        sty2.configure("Mal.Treeview.Heading",background=T["BG_ELEVATED"],foreground="#FF8C42",font=("Consolas",9,"bold"))
        tf=tk.Frame(parent,bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        self.mal_tree=ttk.Treeview(tf,columns=cols,show="headings",style="Mal.Treeview")
        for col,w in zip(cols,[180,60,80,90,300,200]):
            self.mal_tree.heading(col,text=col); self.mal_tree.column(col,width=w,anchor="w")
        for tag,fg in [("CRITICAL",T["RED"]),("HIGH",T["ORANGE"]),("MEDIUM",T["YELLOW"]),("CLEAN",T["GREEN"])]:
            self.mal_tree.tag_configure(tag,foreground=fg)
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.mal_tree.yview)
        self.mal_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.mal_tree.pack(fill=tk.BOTH,expand=True)
        self._mal_scanner=None
    def _on_mal_scan(self):
        path=self.mal_path.get()
        if not os.path.isdir(path): messagebox.showerror("Error",f"Not found: {path}"); return
        for r in self.mal_tree.get_children(): self.mal_tree.delete(r)
        self.mal_prog.start(8); self.btn_mal.configure(state=tk.DISABLED,text="◉ SCANNING...")
        from malware_scanner import MalwareScanner
        self._mal_scanner=MalwareScanner()  # no progress_callback arg
        threading.Thread(target=self._mal_bg,args=(path,),daemon=True).start()
    def _stop_mal_scan(self):
        if self._mal_scanner: self._mal_scanner.stop()
    def _mal_bg(self,path):
        try:
            results=self._mal_scanner.scan_directory(path)
            self._ui(lambda:self._show_mal(results))
        except Exception as e: self._ui(lambda:self.mal_stats_var.set(f"Error:{e}"))
        finally: self._ui(self._mal_done)
    def _mal_done(self):
        self.mal_prog.stop(); self.btn_mal.configure(state=tk.NORMAL,text="🔍 SCAN")
    def _show_mal(self,results):
        s=self._mal_scanner.stats
        self.mal_stats_var.set(f"Scanned:{s['scanned']}  Suspicious:{s['suspicious']}  Critical:{s['critical']}")
        if not results:
            self.mal_tree.insert("","end",values=("✓ No threats","","","CLEAN","All files safe",""),tags=("CLEAN",)); return
        for r in results:
            finding=r["findings"][0]["detail"][:60] if r["findings"] else ""
            self.mal_tree.insert("","end",values=(r["name"],r["ext"],r["size_kb"],r["severity"],finding,r["path"][:50]),tags=(r["severity"],))

    def _tab_usb(self,parent):
        tk.Label(parent,text="  ◈  USB DEVICE MONITOR",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg="#AA44FF",anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg="#AA44FF",height=2).pack(fill=tk.X)
        row=tk.Frame(parent,bg=T["BG_PANEL"],padx=14,pady=8); row.pack(fill=tk.X)
        tk.Button(row,text="🔄 REFRESH",font=("Consolas",9,"bold"),bg="#AA44FF",fg=T["BG_DEEP"],
                  relief=tk.FLAT,cursor="hand2",padx=12,pady=6,command=self._usb_refresh).pack(side=tk.RIGHT)
        self.usb_status_var=tk.StringVar(value="Monitoring USB...")
        tk.Label(parent,textvariable=self.usb_status_var,font=("Consolas",9),
                 bg=T["BG_ELEVATED"],fg="#AA44FF",anchor="w",padx=14,pady=5).pack(fill=tk.X)
        cols=("Device","Class","Risk","Whitelisted","Status","ID")
        sty=ttk.Style(); sty.configure("USB.Treeview",background=T["BG_CARD"],foreground=T["TEXT_MID"],
            fieldbackground=T["BG_CARD"],rowheight=26,font=("Consolas",8))
        sty.configure("USB.Treeview.Heading",background=T["BG_ELEVATED"],foreground="#AA44FF",font=("Consolas",8,"bold"))
        tf=tk.Frame(parent,bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        self.usb_dev_tree=ttk.Treeview(tf,columns=cols,show="headings",style="USB.Treeview")
        for col,w in zip(cols,[220,120,80,100,80,200]):
            self.usb_dev_tree.heading(col,text=col); self.usb_dev_tree.column(col,width=w,anchor="w")
        for tag,fg in [("HIGH",T["RED"]),("MEDIUM",T["ORANGE"]),("LOW",T["GREEN"])]:
            self.usb_dev_tree.tag_configure(tag,foreground=fg)
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.usb_dev_tree.yview)
        self.usb_dev_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.usb_dev_tree.pack(fill=tk.BOTH,expand=True)
        btn_row=tk.Frame(parent,bg=T["BG_DEEP"]); btn_row.pack(anchor="w",padx=8,pady=4)
        tk.Button(btn_row,text="✓ WHITELIST SELECTED",font=("Consolas",8),bg=T["GREEN_DIM"],
                  fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",padx=8,pady=4,
                  command=self._usb_whitelist).pack(side=tk.LEFT)
        self.usb_log=tk.Text(parent,font=("Consolas",8),bg=T["LOG_BG"],fg=T["TEXT_MID"],
                              relief=tk.FLAT,padx=8,pady=4,state=tk.DISABLED,height=5)
        self.usb_log.pack(fill=tk.X,padx=8); self.usb_log.tag_configure("new",foreground=T["ORANGE"])
        self.after(550, self._usb_refresh)
    def _usb_refresh(self):
        threading.Thread(target=self._usb_bg,daemon=True).start()
    def _usb_bg(self):
        try:
            # USBMonitor tracks events, get current list via psutil
            import psutil
            devs = []
            for disk in psutil.disk_partitions():
                if 'removable' in disk.opts.lower() or disk.fstype in ('FAT32','exFAT','FAT'):
                    devs.append({'path': disk.mountpoint, 'fstype': disk.fstype,
                                 'device': disk.device, 'status': 'Connected'})
            if not devs:
                devs = [{'path':'No USB drives', 'fstype':'','device':'','status':''}]
            self._ui(lambda d=devs: self._show_usb(d))
        except Exception as ex:
            self._ui(lambda e=str(ex): self.usb_status_var.set("Error: " + e))
    def _show_usb(self,devices):
        for r in self.usb_dev_tree.get_children(): self.usb_dev_tree.delete(r)
        for d in devices:
            wl="YES ✓" if d.get("whitelisted") else "NO"
            self.usb_dev_tree.insert("","end",values=(d["name"],d["class"],d["risk_level"],
                wl,d["status"],d["id"][:40]),tags=(d["risk_level"],))
        self.usb_status_var.set(f"{len(devices)} USB device(s) connected")
    def _on_usb_event(self,event):
        try:
            self._ui( lambda e=event: self._usb_log_event(e))
        except RuntimeError: pass
    def _usb_log_event(self,event):
        self.usb_log.configure(state=tk.NORMAL)
        self.usb_log.insert(tk.END,f"[{event.get('time','')}] NEW USB: {event.get('name','?')}  Risk:{event.get('risk_level','?')}\n","new")
        self.usb_log.see(tk.END); self.usb_log.configure(state=tk.DISABLED)
        if event.get("risk_level")=="HIGH":
            self._show_alert_popup({"severity":"HIGH","title":"⚠ Suspicious USB!",
                "message":f"Device: {event.get('name','?')}\nRisk: HIGH","time":event.get("time","")})
        self._usb_refresh()
    def _usb_whitelist(self):
        sel=self.usb_dev_tree.selection()
        if not sel: messagebox.showwarning("Select","Select a device"); return
        uid=self.usb_dev_tree.item(sel[0])["values"][-1]
        self.usb_monitor.add_to_whitelist(uid)
        messagebox.showinfo("Whitelisted","Device whitelisted."); self._usb_refresh()

    def _tab_report_card(self,parent):
        tk.Label(parent,text="  ◈  SECURITY GRADE REPORT CARD",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg=T["YELLOW"],anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg=T["YELLOW"],height=2).pack(fill=tk.X)
        tk.Button(parent,text="📊  GENERATE REPORT CARD",font=("Consolas",11,"bold"),
                  bg=T["YELLOW"],fg=T["BG_DEEP"],relief=tk.FLAT,cursor="hand2",
                  padx=16,pady=8,command=self._gen_report_card).pack(pady=10)
        self.rc_frame=tk.Frame(parent,bg=T["BG_DEEP"]); self.rc_frame.pack(fill=tk.BOTH,expand=True,padx=10)
        tk.Label(self.rc_frame,text="Run a vulnerability scan first, then click GENERATE REPORT CARD",
                 font=("Consolas",12),bg=T["BG_DEEP"],fg=T["TEXT_DIM"]).pack(expand=True)
    def _gen_report_card(self):
        if not self.scan_results or not self.risk_result:
            messagebox.showwarning("No Data","Run a scan first!"); return
        try:
            from report_card import generate_report_card
            card=generate_report_card(self.scan_results,self.risk_result)
            self._render_report_card(card)
        except Exception as e: messagebox.showerror("Error",str(e))
    def _render_report_card(self,card):
        for w in self.rc_frame.winfo_children(): w.destroy()
        grade=card["grade"]; gc=card["grade_color"]; score=card["overall_score"]
        top=tk.Frame(self.rc_frame,bg=T["BG_DEEP"]); top.pack(fill=tk.X)
        gcanvas=tk.Canvas(top,width=160,height=160,bg=T["BG_DEEP"],highlightthickness=0); gcanvas.pack(side=tk.LEFT,padx=20,pady=10)
        gcanvas.create_oval(10,10,150,150,fill=T["BG_CARD"],outline=gc,width=6)
        gcanvas.create_text(80,65,text=grade,font=("Consolas",52,"bold"),fill=gc)
        gcanvas.create_text(80,110,text=f"{score}/100",font=("Consolas",11),fill=T["TEXT_DIM"])
        gcanvas.create_text(80,130,text=card["grade_label"],font=("Consolas",9,"bold"),fill=gc)
        info=tk.Frame(top,bg=T["BG_DEEP"]); info.pack(side=tk.LEFT,fill=tk.BOTH,expand=True,pady=10)
        tk.Label(info,text=f"GRADE: {grade} — {card['grade_desc']}",font=("Consolas",14,"bold"),
                 bg=T["BG_DEEP"],fg=gc,anchor="w",wraplength=500).pack(fill=tk.X)
        tk.Label(info,text=f"Risk: {card['risk_level']}  |  Open Ports: {card['open_port_count']}  |  Critical Ports: {card['crit_port_count']}",
                 font=("Consolas",9),bg=T["BG_DEEP"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X,pady=4)
        tk.Frame(self.rc_frame,bg=T["TEXT_DIM"],height=1).pack(fill=tk.X,padx=10,pady=6)
        cats_frame=tk.Frame(self.rc_frame,bg=T["BG_DEEP"]); cats_frame.pack(fill=tk.X,padx=10)
        row_f=None
        for i,(cat_name,cat_data) in enumerate(card["categories"].items()):
            if i%3==0: row_f=tk.Frame(cats_frame,bg=T["BG_DEEP"]); row_f.pack(fill=tk.X)
            cdf=tk.Frame(row_f,bg=T["BG_CARD"],padx=12,pady=10); cdf.pack(side=tk.LEFT,fill=tk.BOTH,expand=True,padx=4,pady=4)
            gc2=cat_data["color"]
            tk.Label(cdf,text=cat_data["grade"],font=("Consolas",28,"bold"),bg=T["BG_CARD"],fg=gc2).pack()
            tk.Label(cdf,text=cat_name,font=("Consolas",8,"bold"),bg=T["BG_CARD"],fg=T["TEXT_DIM"]).pack()
            tk.Label(cdf,text=f"{cat_data['score']}/100",font=("Consolas",7),bg=T["BG_CARD"],fg=T["TEXT_DIM"]).pack()
            bar=MiniBar(cdf,width=130,height=8,color=gc2,bg=T["BG_CARD"]); bar.pack(pady=2); bar.set_value(cat_data["score"],gc2)

    def _tab_attack_sim(self,parent):
        tk.Label(parent,text="  ◈  ETHICAL ATTACK SIMULATION LAB",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg="#FF2D55",anchor="w",pady=10).pack(fill=tk.X)
        tk.Label(parent,text="  Educational only — safe simulations — localhost only",
                 font=("Segoe UI",8),bg=T["BG_PANEL"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X)
        tk.Frame(parent,bg="#FF2D55",height=2).pack(fill=tk.X)
        content=tk.Frame(parent,bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH,expand=True)
        left=tk.Frame(content,bg=T["BG_PANEL"],width=260); left.pack(side=tk.LEFT,fill=tk.Y); left.pack_propagate(False)
        tk.Frame(left,bg="#FF2D55",height=2).pack(fill=tk.X)
        tk.Label(left,text="SIMULATIONS",font=("Consolas",9,"bold"),
                 bg=T["BG_PANEL"],fg="#FF2D55",pady=6,padx=10,anchor="w").pack(fill=tk.X)
        from attack_simulator import SIMULATIONS as SIM_LIST, AttackSimulator as AS
        for sim in SIM_LIST:
            card=tk.Frame(left,bg=T["BG_CARD"],cursor="hand2"); card.pack(fill=tk.X,padx=8,pady=3)
            tk.Frame(card,bg=sim["color"],width=3).pack(side=tk.LEFT,fill=tk.Y)
            inf=tk.Frame(card,bg=T["BG_CARD"],padx=8,pady=6); inf.pack(side=tk.LEFT,fill=tk.X,expand=True)
            tk.Label(inf,text=sim["title"],font=("Consolas",8,"bold"),bg=T["BG_CARD"],fg=sim["color"],anchor="w").pack(fill=tk.X)
            tk.Label(inf,text=sim["difficulty"],font=("Consolas",7),bg=T["BG_CARD"],fg=T["TEXT_DIM"],anchor="w").pack(fill=tk.X)
            card.bind("<Button-1>",lambda e,sid=sim["id"]:self._run_sim(sid))
            for ch in card.winfo_children(): ch.bind("<Button-1>",lambda e,sid=sim["id"]:self._run_sim(sid))
        right=tk.Frame(content,bg=T["BG_DEEP"]); right.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        self.sim_title_lbl=tk.Label(right,text="← Select simulation",font=("Consolas",10,"bold"),
                                     bg=T["BG_CARD"],fg="#FF2D55",padx=10,pady=6); self.sim_title_lbl.pack(fill=tk.X)
        ow=tk.Frame(right,bg=T["LOG_BG"]); ow.pack(fill=tk.BOTH,expand=True,padx=4,pady=4)
        self.sim_out=tk.Text(ow,font=("Consolas",9),bg=T["LOG_BG"],fg=T["TEXT_MID"],
                              relief=tk.FLAT,padx=12,pady=8,wrap=tk.WORD,state=tk.DISABLED)
        self.sim_out.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        sovsb=tk.Scrollbar(ow,orient=tk.VERTICAL,command=self.sim_out.yview)
        sovsb.pack(side=tk.RIGHT,fill=tk.Y); self.sim_out.configure(yscrollcommand=sovsb.set)
        for tag,fg,fnt in [("title","#FF2D55",("Consolas",10,"bold")),("step",T["CYAN"],None),
            ("warn",T["ORANGE"],None),("success",T["GREEN"],("Consolas",9,"bold")),
            ("sep",T["TEXT_DIM"],None),("open_port",T["RED"],("Consolas",9,"bold")),
            ("closed_port",T["TEXT_DIM"],("Consolas",8)),("result",T["YELLOW"],("Consolas",9,"bold")),
            ("info",T["TEXT_MID"],None),("error",T["RED"],None)]:
            self.sim_out.tag_configure(tag,foreground=fg,**({"font":fnt} if fnt else {}))
    def _run_sim(self,sim_id):
        from attack_simulator import SIMULATIONS as SIM_LIST, AttackSimulator as AS
        sim=next((s for s in SIM_LIST if s["id"]==sim_id),None)
        if not sim: return
        self.sim_title_lbl.configure(text=f"▶ {sim['title']}",fg=sim["color"])
        self.sim_out.configure(state=tk.NORMAL); self.sim_out.delete(1.0,tk.END); self.sim_out.configure(state=tk.DISABLED)
        self.attack_sim=AS(output_callback=self._on_sim_output)
        threading.Thread(target=self.attack_sim.run_simulation,args=(sim_id,),daemon=True).start()
    def _on_sim_output(self,msg,tag="info"):
        try:
            self._ui( lambda m=msg, t=tag: self._append_sim(m, t))
        except RuntimeError: pass
    def _append_sim(self,msg,tag):
        self.sim_out.configure(state=tk.NORMAL)
        self.sim_out.insert(tk.END,msg+"\n",tag)
        self.sim_out.see(tk.END); self.sim_out.configure(state=tk.DISABLED)

    def _tab_breach(self,parent):
        tk.Label(parent,text="  ◈  DATA BREACH CHECKER",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg="#AA44FF",anchor="w",pady=10).pack(fill=tk.X)
        tk.Frame(parent,bg="#AA44FF",height=2).pack(fill=tk.X)
        content=tk.Frame(parent,bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH,expand=True,padx=20,pady=16)
        # Email
        ec=tk.Frame(content,bg=T["BG_CARD"],padx=16,pady=14); ec.pack(fill=tk.X)
        tk.Frame(ec,bg="#AA44FF",height=2).pack(fill=tk.X,pady=(0,8))
        tk.Label(ec,text="CHECK EMAIL FOR BREACHES",font=("Consolas",10,"bold"),bg=T["BG_CARD"],fg="#AA44FF",anchor="w").pack(fill=tk.X)
        er=tk.Frame(ec,bg=T["BG_CARD"]); er.pack(fill=tk.X,pady=6)
        self.breach_email=tk.StringVar()
        ef=tk.Frame(er,bg=T["CYAN_DIM"],padx=1,pady=1); ef.pack(side=tk.LEFT,fill=tk.X,expand=True)
        tk.Entry(ef,textvariable=self.breach_email,font=("Consolas",11),bg=T["BG_DEEP"],
                 fg=T["GREEN"],insertbackground=T["GREEN"],relief=tk.FLAT,bd=5).pack(fill=tk.X)
        tk.Button(er,text="🔍 CHECK",font=("Consolas",9,"bold"),bg="#AA44FF",fg=T["BG_DEEP"],
                  relief=tk.FLAT,cursor="hand2",padx=12,pady=4,command=self._check_breach_email).pack(side=tk.LEFT,padx=8)
        self.breach_email_result=tk.Label(ec,text="",font=("Segoe UI",9),bg=T["BG_CARD"],
                                           fg=T["TEXT_DIM"],wraplength=700,justify=tk.LEFT); self.breach_email_result.pack(fill=tk.X,pady=4)
        # Password
        pc=tk.Frame(content,bg=T["BG_CARD"],padx=16,pady=14); pc.pack(fill=tk.X,pady=(12,0))
        tk.Frame(pc,bg=T["CYAN"],height=2).pack(fill=tk.X,pady=(0,8))
        tk.Label(pc,text="CHECK PASSWORD (k-ANONYMITY — password never sent to server)",
                 font=("Consolas",9,"bold"),bg=T["BG_CARD"],fg=T["CYAN"],anchor="w").pack(fill=tk.X)
        pr=tk.Frame(pc,bg=T["BG_CARD"]); pr.pack(fill=tk.X,pady=6)
        self.breach_pw=tk.StringVar()
        pf=tk.Frame(pr,bg=T["CYAN_DIM"],padx=1,pady=1); pf.pack(side=tk.LEFT,fill=tk.X,expand=True)
        tk.Entry(pf,textvariable=self.breach_pw,font=("Consolas",11),show="●",bg=T["BG_DEEP"],
                 fg=T["GREEN"],insertbackground=T["GREEN"],relief=tk.FLAT,bd=5).pack(fill=tk.X)
        tk.Button(pr,text="🔍 CHECK",font=("Consolas",9,"bold"),bg=T["CYAN"],fg=T["BG_DEEP"],
                  relief=tk.FLAT,cursor="hand2",padx=12,pady=4,command=self._check_breach_pw).pack(side=tk.LEFT,padx=8)
        self.breach_pw_result=tk.Label(pc,text="",font=("Segoe UI",9),bg=T["BG_CARD"],
                                        fg=T["TEXT_DIM"],wraplength=700,justify=tk.LEFT); self.breach_pw_result.pack(fill=tk.X,pady=4)
        # Recent breaches
        rb=tk.Frame(content,bg=T["BG_CARD"],padx=16,pady=12); rb.pack(fill=tk.BOTH,expand=True,pady=(12,0))
        tk.Frame(rb,bg=T["RED"],height=2).pack(fill=tk.X,pady=(0,8))
        tk.Label(rb,text="KNOWN MAJOR BREACHES",font=("Consolas",9,"bold"),bg=T["BG_CARD"],fg=T["RED"],anchor="w").pack(fill=tk.X)
        cols=("Name","Date","Accounts","Domain")
        sty=ttk.Style(); sty.configure("Br.Treeview",background=T["BG_ELEVATED"],foreground=T["TEXT_MID"],
            fieldbackground=T["BG_ELEVATED"],rowheight=24,font=("Consolas",8))
        sty.configure("Br.Treeview.Heading",background=T["BG_CARD"],foreground="#AA44FF",font=("Consolas",8,"bold"))
        self.breach_tree=ttk.Treeview(rb,columns=cols,show="headings",style="Br.Treeview",height=6)
        for col,w in zip(cols,[200,100,160,160]):
            self.breach_tree.heading(col,text=col); self.breach_tree.column(col,width=w,anchor="w")
        self.breach_tree.pack(fill=tk.BOTH,expand=True)
        self.after(600, lambda: threading.Thread(target=self._load_recent_breaches,daemon=True).start())
    def _check_breach_email(self):
        email=self.breach_email.get().strip()
        if not email: return
        self.breach_email_result.configure(text="Checking...",fg=T["TEXT_DIM"])
        threading.Thread(target=lambda:self._breach_email_bg(email),daemon=True).start()
    def _breach_email_bg(self,email):
        from breach_checker import check_email
        r=check_email(email)
        def upd():
            if "error" in r: self.breach_email_result.configure(text=f"Error: {r['error']}\n(Free API key: haveibeenpwned.com/API/Key)",fg=T["ORANGE"])
            elif r.get("pwned"): self.breach_email_result.configure(text=r["summary"],fg=T["RED"])
            else: self.breach_email_result.configure(text=r.get("summary","Not found"),fg=T["GREEN"])
        self._ui(upd)
    def _check_breach_pw(self):
        pw=self.breach_pw.get()
        if not pw: return
        self.breach_pw_result.configure(text="Checking...",fg=T["TEXT_DIM"])
        threading.Thread(target=lambda:self._breach_pw_bg(pw),daemon=True).start()
    def _breach_pw_bg(self,pw):
        from breach_checker import check_password_pwned
        r=check_password_pwned(pw)
        def upd():
            if "error" in r: self.breach_pw_result.configure(text=f"Error: {r['error']}",fg=T["ORANGE"])
            elif r.get("pwned"): self.breach_pw_result.configure(text=f"{r['summary']}\n{r['advice']}",fg=T["RED"])
            else: self.breach_pw_result.configure(text=f"{r['summary']}\n{r['advice']}",fg=T["GREEN"])
        self._ui(upd)
    def _load_recent_breaches(self):
        breaches=get_latest_breaches(10)
        def upd():
            for b in breaches:
                cnt=b.get("PwnCount",0)
                self.breach_tree.insert("","end",values=(b.get("Name","?"),b.get("BreachDate","--"),f"{cnt:,}" if cnt else "--",b.get("Domain","--")))
        self._ui(upd)

    def _tab_news(self,parent):
        hdr=tk.Frame(parent,bg=T["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr,bg=T["CYAN"],height=2).pack(fill=tk.X)
        row=tk.Frame(hdr,bg=T["BG_PANEL"],pady=10,padx=14); row.pack(fill=tk.X)
        tk.Label(row,text="◈  LIVE CYBERSECURITY NEWS FEED",font=("Consolas",11,"bold"),
                 bg=T["BG_PANEL"],fg=T["CYAN"]).pack(side=tk.LEFT)
        self.btn_news=tk.Button(row,text="🔄 REFRESH",font=("Consolas",10,"bold"),bg=T["CYAN"],fg=T["BG_DEEP"],
                                 relief=tk.FLAT,cursor="hand2",padx=14,pady=6,command=self._load_news)
        self.btn_news.pack(side=tk.RIGHT)
        sty=ttk.Style(); sty.configure("News.Horizontal.TProgressbar",troughcolor=T["BG_CARD"],background=T["CYAN"],thickness=3)
        self.news_prog=ttk.Progressbar(row,mode="indeterminate",length=120,style="News.Horizontal.TProgressbar")
        self.news_prog.pack(side=tk.RIGHT,padx=8)
        self.news_status_var=tk.StringVar(value="Click REFRESH to load latest news...")
        tk.Label(parent,textvariable=self.news_status_var,font=("Consolas",9),
                 bg=T["BG_ELEVATED"],fg=T["CYAN"],anchor="w",padx=14,pady=5).pack(fill=tk.X)
        canvas=tk.Canvas(parent,bg=T["BG_DEEP"],highlightthickness=0)
        vsb=tk.Scrollbar(parent,orient=tk.VERTICAL,command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        canvas.pack(side=tk.LEFT,fill=tk.BOTH,expand=True)
        self.news_inner=tk.Frame(canvas,bg=T["BG_DEEP"])
        nw=canvas.create_window((0,0),window=self.news_inner,anchor="nw")
        self.news_inner.bind("<Configure>",lambda e:canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>",lambda e:canvas.itemconfig(nw,width=e.width))
        canvas.bind_all("<MouseWheel>",lambda e:canvas.yview_scroll(int(-1*(e.delta/120)),"units"))
    def _load_news(self):
        self.btn_news.configure(state=tk.DISABLED,text="◉ LOADING..."); self.news_prog.start(10)
        for w in self.news_inner.winfo_children(): w.destroy()
        threading.Thread(target=self._news_bg,daemon=True).start()
    def _news_bg(self):
        from security_news import fetch_news
        arts=fetch_news(); self._ui(lambda:self._show_news(arts))
    def _show_news(self,articles):
        self.news_prog.stop(); self.btn_news.configure(state=tk.NORMAL,text="🔄 REFRESH")
        if not articles:
            tk.Label(self.news_inner,text="No articles — check internet",
                     font=("Consolas",11),bg=T["BG_DEEP"],fg=T["TEXT_DIM"]).pack(pady=20); return
        for a in articles:
            card=tk.Frame(self.news_inner,bg=T["BG_CARD"]); card.pack(fill=tk.X,padx=10,pady=4)
            hdr_r=tk.Frame(card,bg=T["BG_ELEVATED"]); hdr_r.pack(fill=tk.X)
            tk.Label(hdr_r,text=f" {a['tag_label']} ",font=("Consolas",7,"bold"),
                     bg=a["tag_color"],fg=T["BG_DEEP"]).pack(side=tk.LEFT)
            tk.Label(hdr_r,text=f"  {a['source']}  |  {a['date'][:16]}",
                     font=("Consolas",7),bg=T["BG_ELEVATED"],fg=T["TEXT_DIM"]).pack(side=tk.LEFT,padx=6)
            body=tk.Frame(card,bg=T["BG_CARD"],padx=12,pady=8); body.pack(fill=tk.X)
            tk.Label(body,text=a["title"],font=("Consolas",9,"bold"),bg=T["BG_CARD"],
                     fg=a["tag_color"],wraplength=900,justify=tk.LEFT,anchor="w").pack(fill=tk.X)
            if a.get("desc"):
                tk.Label(body,text=a["desc"][:200],font=("Segoe UI",8),bg=T["BG_CARD"],
                         fg=T["TEXT_DIM"],wraplength=900,justify=tk.LEFT,anchor="w").pack(fill=tk.X,pady=(3,0))
            if a.get("link"):
                def _open(url=a["link"]):
                    try: import webbrowser; webbrowser.open(url)
                    except: pass
                tk.Button(body,text="→ Read Article",font=("Consolas",7),
                          bg=T["BG_ELEVATED"],fg=T["CYAN"],relief=tk.FLAT,cursor="hand2",
                          padx=6,pady=2,command=_open).pack(anchor="w",pady=(4,0))
        self.news_status_var.set(f"✓ {len(articles)} articles  |  {datetime.now().strftime('%H:%M')}")

    # ══════════════════════════════════════════════════════════════════════

    def _tab_2fa(self, parent):
        tk.Label(parent, text="  ◈  TWO-FACTOR AUTHENTICATION SETUP", font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["GREEN"], anchor="w", pady=10).pack(fill=tk.X)
        tk.Label(parent, text="  TOTP-based 2FA — Google/Microsoft Authenticator compatible", font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["GREEN"], height=2).pack(fill=tk.X)
        content = tk.Frame(parent, bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH, expand=True, padx=20, pady=16)
        # Secret generation
        sec = tk.Frame(content, bg=T["BG_CARD"], padx=16, pady=14); sec.pack(fill=tk.X)
        tk.Frame(sec, bg=T["GREEN"], height=2).pack(fill=tk.X, pady=(0,8))
        tk.Label(sec, text="SECRET KEY:", font=("Consolas",9,"bold"), bg=T["BG_CARD"], fg=T["GREEN"], anchor="w").pack(fill=tk.X)
        self.otp_secret_var = tk.StringVar(value=generate_secret())
        sr = tk.Frame(sec, bg=T["BG_CARD"]); sr.pack(fill=tk.X, pady=6)
        sf = tk.Frame(sr, bg=T["CYAN_DIM"], padx=1, pady=1); sf.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Entry(sf, textvariable=self.otp_secret_var, font=("Consolas",11,"bold"), bg=T["BG_DEEP"], fg=T["GREEN"], insertbackground=T["GREEN"], relief=tk.FLAT, bd=5, state="readonly").pack(fill=tk.X)
        tk.Button(sr, text="↻ NEW", font=("Consolas",9), bg=T["BG_ELEVATED"], fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=8, pady=4, command=lambda: self.otp_secret_var.set(generate_secret())).pack(side=tk.LEFT, padx=6)
        tk.Button(sr, text="📋 COPY", font=("Consolas",9), bg=T["BG_ELEVATED"], fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=8, pady=4, command=lambda: (self.clipboard_clear(), self.clipboard_append(self.otp_secret_var.get()))).pack(side=tk.LEFT)
        self.otp_user_var = tk.StringVar(value=self.logged_in_user)
        ur = tk.Frame(sec, bg=T["BG_CARD"]); ur.pack(fill=tk.X, pady=6)
        tk.Label(ur, text="Username:", font=("Consolas",8), bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,6))
        uf = tk.Frame(ur, bg=T["CYAN_DIM"], padx=1, pady=1); uf.pack(side=tk.LEFT)
        tk.Entry(uf, textvariable=self.otp_user_var, font=("Consolas",10), width=14, bg=T["BG_DEEP"], fg=T["GREEN"], insertbackground=T["GREEN"], relief=tk.FLAT, bd=4).pack()
        tk.Button(ur, text="💾 SAVE 2FA", font=("Consolas",9,"bold"), bg=T["GREEN_DIM"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=12, pady=5, command=self._otp_save).pack(side=tk.LEFT, padx=10)
        self.otp_uri_lbl = tk.Label(sec, text="", font=("Consolas",7), bg=T["BG_CARD"], fg=T["TEXT_DIM"], wraplength=700, anchor="w"); self.otp_uri_lbl.pack(fill=tk.X)
        # Verify
        ver = tk.Frame(content, bg=T["BG_CARD"], padx=16, pady=14); ver.pack(fill=tk.X, pady=(10,0))
        tk.Frame(ver, bg=T["CYAN"], height=2).pack(fill=tk.X, pady=(0,8))
        tk.Label(ver, text="VERIFY CODE — enter code from authenticator app:", font=("Consolas",9,"bold"), bg=T["BG_CARD"], fg=T["CYAN"], anchor="w").pack(fill=tk.X)
        vr = tk.Frame(ver, bg=T["BG_CARD"]); vr.pack(fill=tk.X, pady=6)
        self.otp_code_var = tk.StringVar()
        cf = tk.Frame(vr, bg=T["CYAN_DIM"], padx=1, pady=1); cf.pack(side=tk.LEFT)
        otp_entry = tk.Entry(cf, textvariable=self.otp_code_var, font=("Consolas",18,"bold"), width=8, bg=T["BG_DEEP"], fg=T["CYAN"], insertbackground=T["CYAN"], relief=tk.FLAT, bd=6, justify="center")
        otp_entry.pack(); otp_entry.bind("<Return>", lambda e: self._otp_verify())
        tk.Button(vr, text="✓ VERIFY", font=("Consolas",10,"bold"), bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=14, pady=6, command=self._otp_verify).pack(side=tk.LEFT, padx=10)
        self.otp_verify_lbl = tk.Label(vr, text="", font=("Consolas",10,"bold"), bg=T["BG_CARD"], fg=T["TEXT_DIM"]); self.otp_verify_lbl.pack(side=tk.LEFT)
        # Live preview
        live = tk.Frame(content, bg=T["BG_CARD"], padx=16, pady=14); live.pack(fill=tk.X, pady=(10,0))
        tk.Frame(live, bg="#AA44FF", height=2).pack(fill=tk.X, pady=(0,8))
        tk.Label(live, text="LIVE OTP PREVIEW:", font=("Consolas",9,"bold"), bg=T["BG_CARD"], fg="#AA44FF", anchor="w").pack(fill=tk.X)
        lr = tk.Frame(live, bg=T["BG_CARD"]); lr.pack(fill=tk.X)
        self.otp_live_var = tk.StringVar(value="------"); self.otp_timer_var = tk.StringVar(value="--s")
        tk.Label(lr, textvariable=self.otp_live_var, font=("Consolas",36,"bold"), bg=T["BG_CARD"], fg="#AA44FF").pack(side=tk.LEFT)
        tk.Label(lr, textvariable=self.otp_timer_var, font=("Consolas",14), bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=12)
        tk.Button(live, text="▶ START LIVE", font=("Consolas",9), bg="#AA44FF", fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=10, pady=4, command=self._otp_start_live).pack(anchor="w", pady=4)
        self._otp_live_running = False

    def _otp_save(self):
        u = self.otp_user_var.get().strip() or "admin"; s = self.otp_secret_var.get().strip()
        save_otp_config(u, s, True)
        self.otp_uri_lbl.configure(text=f"URI: {get_qr_uri(u, s)}")
        messagebox.showinfo("2FA Saved", f"2FA enabled for: {u}\n\nManual setup:\n1. Google Authenticator\n2. + Add account > Enter key\n3. Key: {s}\n4. Account: {u}")

    def _otp_verify(self):
        s = self.otp_secret_var.get().strip(); c = self.otp_code_var.get().strip()
        if not c: self.otp_verify_lbl.configure(text="Enter code", fg=T["ORANGE"]); return
        if verify_totp(s, c): self.otp_verify_lbl.configure(text="✓ VALID — 2FA working!", fg=T["GREEN"])
        else: self.otp_verify_lbl.configure(text="✗ INVALID — check time/secret", fg=T["RED"])

    def _otp_start_live(self):
        self._otp_live_running = True; self._otp_tick()

    def _otp_tick(self):
        if not self._otp_live_running: return
        code, rem = generate_totp(self.otp_secret_var.get().strip())
        self.otp_live_var.set(code); self.otp_timer_var.set(f"{rem}s")
        self.after(1000, self._otp_tick)

    def _tab_speedtest(self, parent):
        tk.Label(parent, text="  ◈  NETWORK SPEED TEST", font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#00AAFF", anchor="w", pady=10).pack(fill=tk.X)
        tk.Label(parent, text="  Download speed, ping, jitter — multi-server test", font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg="#00AAFF", height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=14, pady=10); ctrl.pack(fill=tk.X)
        self.btn_speed = tk.Button(ctrl, text="▶  START SPEED TEST", font=("Consolas",11,"bold"), bg="#00AAFF", fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=16, pady=8, command=self._run_speedtest); self.btn_speed.pack(side=tk.LEFT)
        sty = ttk.Style(); sty.configure("Sp.Horizontal.TProgressbar", troughcolor=T["BG_CARD"], background="#00AAFF", thickness=6)
        self.speed_prog = ttk.Progressbar(ctrl, mode="indeterminate", length=200, style="Sp.Horizontal.TProgressbar"); self.speed_prog.pack(side=tk.LEFT, padx=14)
        self.speed_grade_var = tk.StringVar(value="")
        tk.Label(ctrl, textvariable=self.speed_grade_var, font=("Consolas",12,"bold"), bg=T["BG_CARD"], fg=T["CYAN"]).pack(side=tk.RIGHT, padx=12)
        res_row = tk.Frame(parent, bg=T["BG_DEEP"]); res_row.pack(fill=tk.X, padx=10, pady=10)
        self.speed_widgets = {}
        for key, label, color in [("download","DOWNLOAD Mbps","#00AAFF"),("ping","BEST PING ms","#00FF88"),("jitter","JITTER ms","#FFD60A")]:
            card = tk.Frame(res_row, bg=T["BG_CARD"]); card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=6)
            tk.Frame(card, bg=color, height=3).pack(fill=tk.X)
            vl = tk.Label(card, text="--", font=("Consolas",32,"bold"), bg=T["BG_CARD"], fg=color); vl.pack(pady=(12,2))
            tk.Label(card, text=label, font=("Consolas",8,"bold"), bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(pady=(0,10))
            self.speed_widgets[key] = vl
        lw = tk.Frame(parent, bg=T["LOG_BG"]); lw.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.speed_log = tk.Text(lw, font=("Consolas",9), bg=T["LOG_BG"], fg=T["TEXT_MID"], relief=tk.FLAT, padx=12, pady=8, wrap=tk.WORD, state=tk.DISABLED)
        self.speed_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        spvsb = tk.Scrollbar(lw, orient=tk.VERTICAL, command=self.speed_log.yview); spvsb.pack(side=tk.RIGHT, fill=tk.Y); self.speed_log.configure(yscrollcommand=spvsb.set)
        for tag, fg in [("good",T["GREEN"]),("info",T["CYAN"]),("warn",T["ORANGE"])]: self.speed_log.tag_configure(tag, foreground=fg)

    def _run_speedtest(self):
        self.btn_speed.configure(state=tk.DISABLED, text="◉ TESTING...")
        self.speed_prog.start(8)
        self.speed_log.configure(state=tk.NORMAL); self.speed_log.delete(1.0, tk.END); self.speed_log.configure(state=tk.DISABLED)
        self._speed_tester = SpeedTester(progress_callback=self._speed_log_cb)
        threading.Thread(target=self._speedtest_bg, daemon=True).start()

    def _speedtest_bg(self):
        results = self._speed_tester.run_full_test()
        self._ui( lambda: self._show_speed_results(results))

    def _speed_log_cb(self, msg):
        self._ui( lambda m=msg: self._append_speed_log(m))

    def _append_speed_log(self, msg):
        self.speed_log.configure(state=tk.NORMAL)
        tag = "good" if ("Mbps" in msg or "ms" in msg) else "info" if "[TEST]" in msg else "warn"
        self.speed_log.insert(tk.END, msg + "\n", tag); self.speed_log.see(tk.END)
        self.speed_log.configure(state=tk.DISABLED)

    def _show_speed_results(self, results):
        self.speed_prog.stop(); self.btn_speed.configure(state=tk.NORMAL, text="▶  START SPEED TEST")
        s = results.get("summary", {})
        self.speed_grade_var.set(s.get("grade","--"))
        self.speed_widgets["download"].configure(text=str(s.get("best_download_mbps","--")))
        bp = s.get("best_ping_ms")
        if bp: self.speed_widgets["ping"].configure(text=str(bp))
        pings = results.get("ping",[])
        if pings:
            jitters = [p.get("jitter",0) for p in pings if p.get("jitter") is not None]
            if jitters: self.speed_widgets["jitter"].configure(text=f"{min(jitters):.1f}")

    def _tab_scoregraph(self, parent):
        tk.Label(parent, text="  ◈  VULNERABILITY SCORE HISTORY GRAPH", font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#FF8C42", anchor="w", pady=10).pack(fill=tk.X)
        tk.Label(parent, text="  Every scan auto-saves — see your security trend over time", font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg="#FF8C42", height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=14, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔄 REFRESH", font=("Consolas",9,"bold"), bg="#FF8C42", fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=12, pady=5, command=self._refresh_graph).pack(side=tk.LEFT)
        tk.Button(ctrl, text="🗑 CLEAR", font=("Consolas",8), bg=T["BG_ELEVATED"], fg=T["TEXT_DIM"], relief=tk.FLAT, cursor="hand2", padx=8, pady=5, command=self._clear_graph).pack(side=tk.LEFT, padx=6)
        self.graph_stats_var = tk.StringVar(value="Run scans to build history graph")
        tk.Label(ctrl, textvariable=self.graph_stats_var, font=("Consolas",9), bg=T["BG_CARD"], fg="#FF8C42").pack(side=tk.LEFT, padx=12)
        stats_row = tk.Frame(parent, bg=T["BG_DEEP"]); stats_row.pack(fill=tk.X, padx=8, pady=6)
        self.graph_stat_widgets = {}
        for key, label, color in [("count","TOTAL SCANS","#00D4FF"),("avg","AVG SCORE","#FF8C42"),("min","BEST","#00FF88"),("max","WORST","#FF2D55"),("trend","TREND","#FFD60A"),("worst_level","WORST LEVEL","#FF2D55")]:
            c = tk.Frame(stats_row, bg=T["BG_CARD"]); c.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=3)
            tk.Frame(c, bg=color, height=2).pack(fill=tk.X)
            vl = tk.Label(c, text="--", font=("Consolas",13,"bold"), bg=T["BG_CARD"], fg=color); vl.pack(pady=(8,2))
            tk.Label(c, text=label, font=("Consolas",7,"bold"), bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(pady=(0,6))
            self.graph_stat_widgets[key] = vl
        self.graph_canvas = tk.Canvas(parent, bg="#020609", highlightthickness=0)
        self.graph_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.graph_canvas.bind("<Configure>", lambda e: self._refresh_graph())
        self._refresh_graph()

    def _refresh_graph(self):
        try:
            data  = score_history_graph.load_graph_data()
            stats = score_history_graph.get_stats(data)
            W = self.graph_canvas.winfo_width() or 800
            H = self.graph_canvas.winfo_height() or 400
            score_history_graph.draw_graph(self.graph_canvas, data, W, H)
            if stats.get("count", 0) > 0:
                self.graph_stats_var.set(
                    str(stats["count"]) + " scans  |  Latest: " +
                    str(stats.get("latest","--")) + " (" +
                    str(stats.get("latest_level","--")) + ")")
                for key, val in stats.items():
                    widgets = getattr(self, "graph_stat_widgets", {})
                    if key in widgets:
                        widgets[key].configure(text=str(val))
        except Exception:
            pass

    def _clear_graph(self):
        if messagebox.askyesno("Clear","Delete all graph history?"):
            score_history_graph.save_graph_data([]); self._refresh_graph()

    def _tab_processes(self, parent):
        hdr = tk.Frame(parent, bg=T["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg="#FF2D55", height=2).pack(fill=tk.X)
        row = tk.Frame(hdr, bg=T["BG_PANEL"], pady=10, padx=14); row.pack(fill=tk.X)
        tk.Label(row, text="◈  LIVE PROCESS MONITOR", font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#FF2D55").pack(side=tk.LEFT)
        tk.Button(row, text="🔄 REFRESH", font=("Consolas",9,"bold"), bg="#FF2D55", fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=12, pady=5, command=self._proc_refresh).pack(side=tk.RIGHT)
        tk.Button(row, text="🚨 SUSPICIOUS ONLY", font=("Consolas",8), bg=T["BG_CARD"], fg=T["ORANGE"], relief=tk.FLAT, cursor="hand2", padx=8, pady=5, command=self._proc_suspicious).pack(side=tk.RIGHT, padx=6)
        tk.Button(row, text="⏱ AUTO", font=("Consolas",8), bg=T["BG_CARD"], fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=8, pady=5, command=self._proc_toggle_auto).pack(side=tk.RIGHT, padx=4)
        self.proc_status = tk.StringVar(value="Click REFRESH to load processes")
        tk.Label(parent, textvariable=self.proc_status, font=("Consolas",9), bg=T["BG_ELEVATED"], fg="#FF2D55", anchor="w", padx=14, pady=5).pack(fill=tk.X)
        fr = tk.Frame(parent, bg=T["BG_CARD"], padx=14, pady=5); fr.pack(fill=tk.X)
        tk.Label(fr, text="FILTER:", font=("Consolas",8), bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,6))
        self.proc_filter = tk.StringVar(); self.proc_filter.trace("w", lambda *a: self._proc_apply_filter())
        ff = tk.Frame(fr, bg=T["CYAN_DIM"], padx=1, pady=1); ff.pack(side=tk.LEFT)
        tk.Entry(ff, textvariable=self.proc_filter, font=("Consolas",9), width=20, bg=T["BG_DEEP"], fg=T["GREEN"], insertbackground=T["GREEN"], relief=tk.FLAT, bd=3).pack()
        cols = ("PID","Process","CPU%","RAM MB","Status","User","Risk","Detail")
        sty = ttk.Style(); sty.configure("Pr.Treeview", background=T["BG_CARD"], foreground=T["TEXT_MID"], fieldbackground=T["BG_CARD"], rowheight=24, font=("Consolas",8)); sty.configure("Pr.Treeview.Heading", background=T["BG_ELEVATED"], foreground="#FF2D55", font=("Consolas",8,"bold"))
        tf = tk.Frame(parent, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.proc_tree = ttk.Treeview(tf, columns=cols, show="headings", style="Pr.Treeview")
        for col, w in zip(cols, [60,180,55,70,80,100,80,280]): self.proc_tree.heading(col, text=col); self.proc_tree.column(col, width=w, anchor="w")
        for tag, fg in [("CRITICAL",T["RED"]),("HIGH",T["ORANGE"]),("MEDIUM",T["YELLOW"]),("normal",T["TEXT_MID"])]: self.proc_tree.tag_configure(tag, foreground=fg)
        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.proc_tree.yview); self.proc_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT, fill=tk.Y); self.proc_tree.pack(fill=tk.BOTH, expand=True)
        tk.Button(parent, text="⛔ KILL SELECTED PROCESS", font=("Consolas",9,"bold"), bg="#3A0A0A", fg=T["RED"], relief=tk.FLAT, cursor="hand2", padx=12, pady=6, command=self._proc_kill).pack(pady=6)
        self._all_processes = []; self._proc_auto = False; self.after(575, self._proc_refresh)

    def _proc_refresh(self): threading.Thread(target=self._proc_bg, daemon=True).start()
    def _proc_bg(self):
        procs = get_processes(); self._ui( lambda: self._proc_show(procs))
    def _proc_show(self, procs):
        self._all_processes = procs; self._proc_apply_filter()
        susp = get_suspicious_processes(procs)
        self.proc_status.set(f"{len(procs)} processes  |  Suspicious: {len(susp)}  |  {datetime.now().strftime('%H:%M:%S')}")
    def _proc_apply_filter(self):
        filt = self.proc_filter.get().lower() if hasattr(self,"proc_filter") else ""
        if not hasattr(self,"proc_tree"): return
        for r in self.proc_tree.get_children(): self.proc_tree.delete(r)
        for p in self._all_processes:
            if filt and filt not in p["name"].lower(): continue
            risk = p.get("risk",""); tag = risk if risk in ("CRITICAL","HIGH","MEDIUM") else "normal"
            self.proc_tree.insert("","end", values=(p["pid"],p["name"],f"{p['cpu']}%",f"{p['ram_pct']:.1f}",p["status"],p.get("user","")[:16],risk or "OK",p.get("risk_desc","")[:50]),tags=(tag,))
    def _proc_suspicious(self):
        for r in self.proc_tree.get_children(): self.proc_tree.delete(r)
        susp = get_suspicious_processes(self._all_processes)
        for p in susp:
            risk = p.get("risk",""); self.proc_tree.insert("","end", values=(p["pid"],p["name"],f"{p['cpu']}%",f"{p['ram_pct']:.1f}",p["status"],p.get("user","")[:16],risk,p.get("risk_desc","")[:60]),tags=(risk,))
        if not susp: self.proc_tree.insert("","end", values=("","✓ No suspicious processes found","","","","","",""))
    def _proc_toggle_auto(self):
        self._proc_auto = not self._proc_auto
        if self._proc_auto: self._proc_auto_tick()
    def _proc_auto_tick(self):
        if self._proc_auto: self._proc_refresh(); self.after(5000, self._proc_auto_tick)
    def _proc_kill(self):
        sel = self.proc_tree.selection()
        if not sel: messagebox.showwarning("Select","Select a process first"); return
        pid_str = self.proc_tree.item(sel[0])["values"][0]; name = self.proc_tree.item(sel[0])["values"][1]
        if messagebox.askyesno("Kill",f"Kill: {name} (PID:{pid_str})?"):
            ok, msg = kill_process(int(str(pid_str))); messagebox.showinfo("Result", msg); self._proc_refresh()

    def _tab_iplookup(self, parent):
        tk.Label(parent, text="  ◈  IP GEOLOCATION TRACKER", font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#AA44FF", anchor="w", pady=10).pack(fill=tk.X)
        tk.Label(parent, text="  Any IP ka country, city, ISP, threat level lookup karo", font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg="#AA44FF", height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=14, pady=10); ctrl.pack(fill=tk.X)
        tk.Label(ctrl, text="IP/HOST:", font=("Consolas",9,"bold"), bg=T["BG_CARD"], fg=T["CYAN_DIM"]).pack(side=tk.LEFT, padx=(0,8))
        self.geo_ip_var = tk.StringVar()
        ipf = tk.Frame(ctrl, bg=T["CYAN_DIM"], padx=1, pady=1); ipf.pack(side=tk.LEFT)
        geo_e = tk.Entry(ipf, textvariable=self.geo_ip_var, font=("Consolas",12), width=18, bg=T["BG_DEEP"], fg=T["GREEN"], insertbackground=T["GREEN"], relief=tk.FLAT, bd=5)
        geo_e.pack(); geo_e.bind("<Return>", lambda e: self._geo_lookup())
        tk.Button(ctrl, text="🔍 LOOKUP", font=("Consolas",10,"bold"), bg="#AA44FF", fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=14, pady=6, command=self._geo_lookup).pack(side=tk.LEFT, padx=8)
        tk.Button(ctrl, text="📍 MY IP", font=("Consolas",9), bg=T["BG_ELEVATED"], fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=8, pady=6, command=self._geo_my_ip).pack(side=tk.LEFT)
        tk.Label(ctrl, text="  Quick:", font=("Consolas",8), bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(16,4))
        for ip in ["8.8.8.8","1.1.1.1","185.220.101.1"]:
            tk.Button(ctrl, text=ip, font=("Consolas",7), bg=T["BG_ELEVATED"], fg=T["TEXT_MID"], relief=tk.FLAT, cursor="hand2", padx=5, pady=3, command=lambda x=ip:(self.geo_ip_var.set(x),self._geo_lookup())).pack(side=tk.LEFT, padx=2)
        res = tk.Frame(parent, bg=T["BG_DEEP"]); res.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        left = tk.Frame(res, bg=T["BG_CARD"], padx=14, pady=12, width=320); left.pack(side=tk.LEFT, fill=tk.Y); left.pack_propagate(False)
        tk.Frame(left, bg="#AA44FF", height=2).pack(fill=tk.X, pady=(0,8))
        self.geo_ip_lbl = tk.Label(left, text="--", font=("Consolas",18,"bold"), bg=T["BG_CARD"], fg="#AA44FF"); self.geo_ip_lbl.pack(anchor="w")
        self.geo_loc_lbl = tk.Label(left, text="Enter IP above", font=("Segoe UI",9), bg=T["BG_CARD"], fg=T["TEXT_MID"], wraplength=280, justify=tk.LEFT); self.geo_loc_lbl.pack(anchor="w", pady=4)
        tk.Frame(left, bg=T["TEXT_DIM"], height=1).pack(fill=tk.X, pady=6)
        self.geo_fields = {}
        for field in ["Country","Region","City","ISP","ASN","Proxy","Hosting","Threat"]:
            fr = tk.Frame(left, bg=T["BG_CARD"]); fr.pack(fill=tk.X, pady=2)
            tk.Label(fr, text=f"{field}:", font=("Consolas",8), bg=T["BG_CARD"], fg=T["TEXT_DIM"], width=10, anchor="w").pack(side=tk.LEFT)
            lbl = tk.Label(fr, text="--", font=("Consolas",8,"bold"), bg=T["BG_CARD"], fg=T["TEXT_BRIGHT"]); lbl.pack(side=tk.LEFT)
            self.geo_fields[field] = lbl
        right = tk.Frame(res, bg=T["BG_DEEP"]); right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,0))
        self.geo_map = tk.Canvas(right, bg="#020D18", highlightthickness=0); self.geo_map.pack(fill=tk.BOTH, expand=True)
        self.geo_map.bind("<Configure>", lambda e: self._geo_draw_map())
        self._geo_result = None; self._geo_draw_map()

    def _geo_my_ip(self):
        threading.Thread(target=lambda:(self.geo_ip_var.set(get_my_ip()), self.after(200, self._geo_lookup)), daemon=True).start()
    def _geo_lookup(self):
        ip = self.geo_ip_var.get().strip()
        if not ip: return
        self.geo_ip_lbl.configure(text="Looking up..."); threading.Thread(target=self._geo_bg, args=(ip,), daemon=True).start()
    def _geo_bg(self, ip): result = lookup_ip(ip); self._ui( lambda: self._geo_show(result))
    def _geo_show(self, r):
        self._geo_result = r
        if "error" in r: self.geo_ip_lbl.configure(text="Error", fg=T["RED"]); self.geo_loc_lbl.configure(text=r["error"]); return
        tc = {"CRITICAL":T["RED"],"HIGH":T["ORANGE"],"MEDIUM":T["YELLOW"],"LOW":T["GREEN"]}.get(r.get("threat_level","LOW"),"#AA44FF")
        self.geo_ip_lbl.configure(text=r["ip"], fg="#AA44FF")
        self.geo_loc_lbl.configure(text=f"{r.get('city','?')}, {r.get('region','?')}, {r.get('country','?')}")
        vals = {"Country":r.get("country","--"),"Region":r.get("region","--"),"City":r.get("city","--"),"ISP":r.get("isp","--")[:35],"ASN":r.get("asn","--")[:30],"Proxy":"YES ⚠" if r.get("proxy") else "No","Hosting":"YES" if r.get("hosting") else "No","Threat":r.get("threat_level","LOW")}
        for field, val in vals.items():
            lbl = self.geo_fields.get(field)
            if lbl:
                fg = tc if field=="Threat" else T["ORANGE"] if "YES" in str(val) and field in ("Proxy","Hosting") else T["TEXT_BRIGHT"]
                lbl.configure(text=str(val), fg=fg)
        self._geo_draw_map()
    def _geo_draw_map(self):
        c = self.geo_map; c.delete("all")
        W = c.winfo_width() or 600; H = c.winfo_height() or 350
        c.create_rectangle(0,0,W,H,fill="#020D18",outline="")
        def ll(lat,lon): return int((lon+180)/360*W), int((90-lat)/180*H)
        for pts, fill in [
            ([(60,-140),(70,-100),(60,-80),(50,-55),(25,-80),(20,-100),(30,-120),(50,-130)],"#0A2A1A"),
            ([(10,-80),(0,-50),(-10,-35),(-55,-70),(-40,-75),(-20,-80)],"#0A2A1A"),
            ([(70,30),(60,40),(45,40),(36,36),(36,6),(44,-10),(60,0),(65,14)],"#0A2A1A"),
            ([(37,10),(37,42),(10,50),(-35,20),(-35,18),(0,-18),(15,-17)],"#0A2A1A"),
            ([(70,30),(70,140),(60,140),(40,130),(10,100),(0,100),(20,60),(30,48),(45,40)],"#0A2A1A"),
            ([(-10,130),(-10,150),(-40,150),(-40,115),(-20,115)],"#0A2A1A")]:
            coords = [v for lat,lon in pts for v in ll(lat,lon)]
            if len(coords)>=4: c.create_polygon(coords, fill=fill, outline="#0F3D28", width=1)
        r = self._geo_result
        if r and r.get("lat") and r.get("lon"):
            x,y = ll(r["lat"],r["lon"])
            tc = {"CRITICAL":T["RED"],"HIGH":T["ORANGE"],"MEDIUM":T["YELLOW"]}.get(r.get("threat_level","LOW"),"#AA44FF")
            for rad in [22,14,6]: c.create_oval(x-rad,y-rad,x+rad,y+rad,fill="",outline=tc,width=1)
            c.create_oval(x-5,y-5,x+5,y+5,fill=tc,outline="white",width=1)
            c.create_text(x,y-28,text=f"{r.get('city','')} {r.get('countryCode','')}",font=("Consolas",8,"bold"),fill=tc)
        px,py = ll(30.4,69.3); c.create_oval(px-5,py-5,px+5,py+5,fill=T["GREEN"],outline="white",width=1); c.create_text(px,py-14,text="YOU",font=("Consolas",7,"bold"),fill=T["GREEN"])

    def _tab_pwvault(self, parent):
        tk.Label(parent, text="  ◈  ENCRYPTED PASSWORD VAULT", font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["YELLOW"], anchor="w", pady=10).pack(fill=tk.X)
        tk.Label(parent, text="  PBKDF2 encrypted local vault — master password protected", font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["YELLOW"], height=2).pack(fill=tk.X)
        self.vault_main = tk.Frame(parent, bg=T["BG_DEEP"]); self.vault_main.pack(fill=tk.BOTH, expand=True)
        self._vault_render()

    def _vault_render(self):
        for w in self.vault_main.winfo_children(): w.destroy()
        if not self._pm.is_unlocked(): self._vault_show_lock()
        else: self._vault_show_entries()

    def _vault_show_lock(self):
        frame = tk.Frame(self.vault_main, bg=T["BG_DEEP"]); frame.pack(expand=True)
        tk.Label(frame, text="🔒", font=("Segoe UI",48), bg=T["BG_DEEP"], fg=T["YELLOW"]).pack(pady=(30,6))
        action = "CREATE VAULT" if not self._pm.vault_exists() else "UNLOCK VAULT"
        tk.Label(frame, text=action, font=("Consolas",14,"bold"), bg=T["BG_DEEP"], fg=T["YELLOW"]).pack()
        tk.Label(frame, text="Enter master password:", font=("Consolas",9), bg=T["BG_DEEP"], fg=T["TEXT_DIM"]).pack(pady=(14,4))
        mpf = tk.Frame(frame, bg=T["YELLOW"], padx=1, pady=1); mpf.pack()
        self._vault_pw = tk.StringVar()
        pw_entry = tk.Entry(mpf, textvariable=self._vault_pw, font=("Consolas",14), show="●", width=22, bg=T["BG_CARD"], fg=T["YELLOW"], insertbackground=T["YELLOW"], relief=tk.FLAT, bd=6)
        pw_entry.pack(); pw_entry.bind("<Return>", lambda e: self._vault_unlock())
        tk.Button(frame, text=f"🔓  {action}", font=("Consolas",11,"bold"), bg=T["YELLOW"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", pady=10, padx=20, command=self._vault_unlock).pack(pady=10)
        self._vault_err = tk.Label(frame, text="", font=("Consolas",9), bg=T["BG_DEEP"], fg=T["RED"]); self._vault_err.pack()

    def _vault_unlock(self):
        pw = self._vault_pw.get()
        if not pw: self._vault_err.configure(text="Enter master password"); return
        if self._pm.unlock(pw): self._pm_unlocked = True; self._vault_render()
        else: self._vault_err.configure(text="Wrong password!")

    def _vault_show_entries(self):
        top = tk.Frame(self.vault_main, bg=T["BG_CARD"], padx=12, pady=8); top.pack(fill=tk.X)
        tk.Label(top, text="🔓 VAULT UNLOCKED", font=("Consolas",10,"bold"), bg=T["BG_CARD"], fg=T["YELLOW"]).pack(side=tk.LEFT)
        tk.Button(top, text="🔒 LOCK", font=("Consolas",8), bg=T["BG_ELEVATED"], fg=T["TEXT_DIM"], relief=tk.FLAT, cursor="hand2", padx=8, command=lambda:(self._pm.lock(),self._vault_render())).pack(side=tk.RIGHT)
        tk.Button(top, text="+ ADD ENTRY", font=("Consolas",9,"bold"), bg=T["YELLOW"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=10, pady=4, command=self._vault_add_dialog).pack(side=tk.RIGHT, padx=8)
        tk.Button(top, text="⚡ GEN PW", font=("Consolas",9), bg=T["BG_ELEVATED"], fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=8, pady=4, command=self._vault_gen_pw).pack(side=tk.RIGHT, padx=4)
        sf = tk.Frame(self.vault_main, bg=T["BG_CARD"], padx=12, pady=5); sf.pack(fill=tk.X)
        self._vault_search = tk.StringVar(); self._vault_search.trace("w", lambda *a: self._vault_load_entries())
        ef = tk.Frame(sf, bg=T["YELLOW"], padx=1, pady=1); ef.pack(side=tk.LEFT)
        tk.Entry(ef, textvariable=self._vault_search, font=("Consolas",10), width=24, bg=T["BG_DEEP"], fg=T["YELLOW"], insertbackground=T["YELLOW"], relief=tk.FLAT, bd=4).pack()
        cols = ("Title","Username","Strength","URL","Modified")
        sty = ttk.Style(); sty.configure("V.Treeview", background=T["BG_CARD"], foreground=T["TEXT_MID"], fieldbackground=T["BG_CARD"], rowheight=28, font=("Consolas",9)); sty.configure("V.Treeview.Heading", background=T["BG_ELEVATED"], foreground=T["YELLOW"], font=("Consolas",9,"bold"))
        tf = tk.Frame(self.vault_main, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.vault_tree = ttk.Treeview(tf, columns=cols, show="headings", style="V.Treeview")
        for col, w in zip(cols, [180,150,90,200,130]): self.vault_tree.heading(col, text=col); self.vault_tree.column(col, width=w, anchor="w")
        for tag, fg in [("STRONG",T["GREEN"]),("GOOD",T["CYAN"]),("MODERATE",T["YELLOW"]),("WEAK",T["ORANGE"]),("VERY WEAK",T["RED"])]: self.vault_tree.tag_configure(tag, foreground=fg)
        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.vault_tree.yview); self.vault_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT, fill=tk.Y); self.vault_tree.pack(fill=tk.BOTH, expand=True)
        self.vault_tree.bind("<Double-1>", lambda e: self._vault_copy_pw())
        br = tk.Frame(self.vault_main, bg=T["BG_PANEL"], pady=6); br.pack(fill=tk.X)
        tk.Button(br, text="📋 COPY PASSWORD", font=("Consolas",9,"bold"), bg=T["YELLOW"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=12, pady=5, command=self._vault_copy_pw).pack(side=tk.LEFT, padx=10)
        tk.Button(br, text="🗑 DELETE", font=("Consolas",8), bg="#3A0A0A", fg=T["RED"], relief=tk.FLAT, cursor="hand2", padx=8, pady=5, command=self._vault_delete).pack(side=tk.LEFT)
        tk.Button(br, text="⚠ SHOW WEAK", font=("Consolas",8), bg=T["BG_ELEVATED"], fg=T["ORANGE"], relief=tk.FLAT, cursor="hand2", padx=8, pady=5, command=self._vault_show_weak).pack(side=tk.RIGHT, padx=10)
        self._vault_load_entries()

    def _vault_load_entries(self):
        q = self._vault_search.get() if hasattr(self,"_vault_search") else ""
        entries = self._pm.search(q) if q else self._pm.get_all()
        if not hasattr(self,"vault_tree"): return
        for r in self.vault_tree.get_children(): self.vault_tree.delete(r)
        for e in entries:
            self.vault_tree.insert("","end",values=(e["title"],e["username"],e.get("strength","?"),e.get("url","")[:40],e.get("modified","")),tags=(e.get("strength","WEAK"),),iid=e["id"])

    def _vault_copy_pw(self):
        sel = self.vault_tree.selection()
        if not sel: return
        entry = next((e for e in self._pm.get_all() if e["id"]==sel[0]),None)
        if entry: self.clipboard_clear(); self.clipboard_append(entry["password"]); self._set_status(f"Password copied: {entry['title']}")

    def _vault_delete(self):
        sel = self.vault_tree.selection()
        if not sel: return
        if messagebox.askyesno("Delete","Delete this entry?"): self._pm.delete_entry(sel[0]); self._vault_load_entries()

    def _vault_show_weak(self):
        weak = self._pm.get_weak_passwords()
        if not weak: messagebox.showinfo("All Good","No weak passwords! 🎉"); return
        msg = f"{len(weak)} weak passwords:\n\n" + "".join(f"• {e['title']} ({e['username']}) — {e['strength']}\n" for e in weak)
        messagebox.showwarning("Weak Passwords", msg)

    def _vault_gen_pw(self):
        pw = self._pm.generate_password(16, True); self.clipboard_clear(); self.clipboard_append(pw)
        messagebox.showinfo("Generated", f"Strong password copied!\n\n{pw}")

    def _vault_add_dialog(self):
        dlg = tk.Toplevel(self); dlg.title("Add Entry"); dlg.geometry("400x320"); dlg.configure(bg=T["BG_DEEP"]); dlg.attributes("-topmost",True)
        tk.Frame(dlg, bg=T["YELLOW"], height=3).pack(fill=tk.X)
        tk.Label(dlg, text="ADD NEW ENTRY", font=("Consolas",11,"bold"), bg=T["BG_DEEP"], fg=T["YELLOW"], pady=8).pack()
        fields = {}
        for label, show in [("Title",""),("Username",""),("Password","●"),("URL",""),("Notes","")]:
            fr = tk.Frame(dlg, bg=T["BG_DEEP"]); fr.pack(fill=tk.X, padx=20, pady=3)
            tk.Label(fr, text=f"{label}:", font=("Consolas",8), bg=T["BG_DEEP"], fg=T["TEXT_DIM"], width=10, anchor="w").pack(side=tk.LEFT)
            var = tk.StringVar(); fields[label] = var
            ef = tk.Frame(fr, bg=T["YELLOW"], padx=1, pady=1); ef.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Entry(ef, textvariable=var, font=("Consolas",10), show=show, bg=T["BG_CARD"], fg=T["YELLOW"], insertbackground=T["YELLOW"], relief=tk.FLAT, bd=4).pack(fill=tk.X)
        def _save():
            if not fields["Title"].get() or not fields["Password"].get(): return
            self._pm.add_entry(title=fields["Title"].get(),username=fields["Username"].get(),password=fields["Password"].get(),url=fields["URL"].get(),notes=fields["Notes"].get()); self._vault_load_entries(); dlg.destroy()
        tk.Button(dlg, text="💾 SAVE", font=("Consolas",10,"bold"), bg=T["YELLOW"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", pady=8, command=_save).pack(pady=10, padx=20, fill=tk.X)


    
    # ══════════════════════════════════════════════════════════════════════
    # TAB: HOME DASHBOARD
    # ══════════════════════════════════════════════════════════════════════

    def _tab_home_dashboard(self, parent):
        """Stunning home dashboard — mission control."""
        import platform, time as _t

        # ── Gradient header ────────────────────────────────────────────
        hdr_canvas = tk.Canvas(parent, height=80, bg=T["BG_DEEP"],
                               highlightthickness=0)
        hdr_canvas.pack(fill=tk.X)

        def _draw_hdr(e=None):
            hdr_canvas.delete("all")
            w = hdr_canvas.winfo_width() or 900
            # Gradient background
            for i in range(80):
                ratio = i / 80
                r = int(5  + 8*ratio)
                g = int(10 + 15*ratio)
                b = int(15 + 30*ratio)
                hdr_canvas.create_line(0,i,w,i, fill=f"#{r:02x}{g:02x}{b:02x}")
            # Accent line
            hdr_canvas.create_rectangle(0,0,w,3, fill=T["CYAN"], outline="")
            # Logo text
            hdr_canvas.create_text(24, 40, anchor="w",
                text="🛡  CYBERSHIELD PRO",
                font=("Consolas",18,"bold"), fill=T["CYAN"])
            hdr_canvas.create_text(26, 62, anchor="w",
                text="AI-Powered Security Command Center  ·  v11.0",
                font=("Consolas",9), fill=T["TEXT_DIM"])
            # Time
            ts = __import__("datetime").datetime.now().strftime("%A, %d %B %Y  |  %H:%M")
            hdr_canvas.create_text(w-20, 40, anchor="e",
                text=ts, font=("Consolas",10,"bold"), fill=T["TEXT_MID"])

        hdr_canvas.bind("<Configure>", _draw_hdr)
        self.after(100, _draw_hdr)

        # ── Main body: left + right ────────────────────────────────────
        body = tk.Frame(parent, bg=T["BG_DEEP"])
        body.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        left  = tk.Frame(body, bg=T["BG_DEEP"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = tk.Frame(body, bg=T["BG_DEEP"], width=300)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        right.pack_propagate(False)

        # ── TOP ROW: 4 big stat cards ──────────────────────────────────
        cards_row = tk.Frame(left, bg=T["BG_DEEP"])
        cards_row.pack(fill=tk.X, padx=8, pady=(8,4))

        self._dash_widgets = {}
        card_defs = [
            ("risk_score",  "RISK SCORE",   "--",   T["CYAN"],   "◉"),
            ("risk_level",  "THREAT LEVEL", "--",   T["ORANGE"], "⚡"),
            ("open_ports",  "OPEN PORTS",   "0",    T["RED"],    "🔓"),
            ("scan_count",  "TOTAL SCANS",  "0",    T["GREEN"],  "📊"),
        ]
        for key, label, default, color, icon in card_defs:
            card = tk.Frame(cards_row, bg=T["BG_CARD"], padx=0, pady=0)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)

            # Color top accent
            tk.Frame(card, bg=color, height=3).pack(fill=tk.X)
            inner = tk.Frame(card, bg=T["BG_CARD"], padx=14, pady=12)
            inner.pack(fill=tk.BOTH, expand=True)

            # Icon + label row
            top_row = tk.Frame(inner, bg=T["BG_CARD"]); top_row.pack(fill=tk.X)
            tk.Label(top_row, text=icon, font=("Segoe UI Emoji",16),
                     bg=T["BG_CARD"], fg=color).pack(side=tk.LEFT)
            tk.Label(top_row, text=label, font=("Consolas",7,"bold"),
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=6)

            # Big value
            val_lbl = tk.Label(inner, text=default,
                               font=("Consolas",32,"bold"),
                               bg=T["BG_CARD"], fg=color)
            val_lbl.pack(anchor="w")
            self._dash_widgets[key] = val_lbl

        # ── MIDDLE ROW: Quick Actions ──────────────────────────────────
        qa_frame = tk.Frame(left, bg=T["BG_DEEP"])
        qa_frame.pack(fill=tk.X, padx=8, pady=4)
        tk.Label(qa_frame, text="QUICK ACTIONS",
                 font=("Consolas",8,"bold"), bg=T["BG_DEEP"],
                 fg=T["TEXT_DIM"]).pack(anchor="w", pady=(0,4))

        actions_row = tk.Frame(qa_frame, bg=T["BG_DEEP"])
        actions_row.pack(fill=tk.X)

        def _go_tab(name):
            for i in range(self.nb.index("end")):
                if name.upper() in self.nb.tab(i,"text").upper():
                    self.nb.select(i); return

        quick_actions = [
            ("🔍 RUN SCAN",       T["CYAN"],   "#00AACF", lambda: _go_tab("SCANNER")),
            ("🌐 NETWORK MAP",    T["GREEN"],  "#009955", lambda: _go_tab("NETWORK")),
            ("📊 MONITOR",        T["ORANGE"], "#CC6600", lambda: _go_tab("MONITOR")),
            ("🔑 WIFI PASSWORDS", T["YELLOW"], "#AA8800", lambda: _go_tab("WIFI PW")),
            ("🤖 AI CHAT",        "#AA44FF",   "#7722CC", lambda: _go_tab("AI CHAT")),
            ("🛡 AUTO-FIX",       T["RED"],    "#CC0022", lambda: _go_tab("AUTO")),
            ("💀 METASPLOIT",     "#FF4444",   "#CC1111", lambda: _go_tab("META")),
            ("📋 REPORT CARD",    T["GREEN"],  "#006633", lambda: _go_tab("REPORT CARD")),
        ]
        for i, (label, bg, hover, cmd) in enumerate(quick_actions):
            btn = tk.Button(actions_row, text=label,
                           font=("Consolas",9,"bold"),
                           bg=bg, fg=T["BG_DEEP"],
                           activebackground=hover,
                           relief=tk.FLAT, cursor="hand2",
                           padx=12, pady=8, command=cmd)
            btn.grid(row=i//4, column=i%4, padx=3, pady=3, sticky="ew")
            actions_row.columnconfigure(i%4, weight=1)

        # ── BOTTOM LEFT: Score history mini-graph ─────────────────────
        graph_frame = tk.Frame(left, bg=T["BG_CARD"])
        graph_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        tk.Frame(graph_frame, bg=T["CYAN"], height=2).pack(fill=tk.X)
        gh_row = tk.Frame(graph_frame, bg=T["BG_CARD"], padx=14, pady=8)
        gh_row.pack(fill=tk.X)
        tk.Label(gh_row, text="📈 SCAN HISTORY GRAPH",
                 font=("Consolas",9,"bold"), bg=T["BG_CARD"],
                 fg=T["CYAN"]).pack(side=tk.LEFT)
        tk.Button(gh_row, text="🔄", font=("Consolas",9),
                  bg=T["BG_ELEVATED"], fg=T["CYAN"], relief=tk.FLAT,
                  cursor="hand2", padx=6, pady=2,
                  command=self._dash_refresh).pack(side=tk.RIGHT)
        self.graph_stats_var = tk.StringVar(value="No scan data yet")
        tk.Label(graph_frame, textvariable=self.graph_stats_var,
                 font=("Consolas",8), bg=T["BG_CARD"],
                 fg=T["TEXT_DIM"], padx=14).pack(anchor="w")
        self.dash_score_canvas = tk.Canvas(graph_frame, bg=T["LOG_BG"],
                                            height=120, highlightthickness=0)
        self.dash_score_canvas.pack(fill=tk.X, padx=8, pady=(0,8))

        # ── RIGHT PANEL ────────────────────────────────────────────────
        # System info card
        sys_card = tk.Frame(right, bg=T["BG_CARD"])
        sys_card.pack(fill=tk.X, padx=8, pady=(8,4))
        tk.Frame(sys_card, bg=T["GREEN"], height=3).pack(fill=tk.X)
        sys_inner = tk.Frame(sys_card, bg=T["BG_CARD"], padx=14, pady=10)
        sys_inner.pack(fill=tk.X)
        tk.Label(sys_inner, text="💻 SYSTEM INFO",
                 font=("Consolas",9,"bold"), bg=T["BG_CARD"],
                 fg=T["GREEN"]).pack(anchor="w", pady=(0,6))
        self._si_widgets = {}
        try:
            import platform
            sys_info = {
                "OS":      platform.system()+" "+platform.release(),
                "Machine": platform.machine(),
                "Python":  platform.python_version(),
                "Host":    platform.node(),
            }
        except Exception:
            sys_info = {"OS":"Windows","Machine":"x64","Python":"3.x","Host":"localhost"}
        for k, v in sys_info.items():
            row = tk.Frame(sys_inner, bg=T["BG_CARD"]); row.pack(fill=tk.X, pady=1)
            tk.Label(row, text=k+":", font=("Consolas",8,"bold"),
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                     width=9, anchor="w").pack(side=tk.LEFT)
            lbl = tk.Label(row, text=v[:22], font=("Consolas",8),
                          bg=T["BG_CARD"], fg=T["TEXT_MID"], anchor="w")
            lbl.pack(side=tk.LEFT)

        # Security checklist card
        chk_card = tk.Frame(right, bg=T["BG_CARD"])
        chk_card.pack(fill=tk.X, padx=8, pady=4)
        tk.Frame(chk_card, bg=T["ORANGE"], height=3).pack(fill=tk.X)
        chk_inner = tk.Frame(chk_card, bg=T["BG_CARD"], padx=14, pady=10)
        chk_inner.pack(fill=tk.X)
        tk.Label(chk_inner, text="🔒 SECURITY CHECKLIST",
                 font=("Consolas",9,"bold"), bg=T["BG_CARD"],
                 fg=T["ORANGE"]).pack(anchor="w", pady=(0,6))
        checklist = [
            ("Run vulnerability scan",       False),
            ("Check open ports",             False),
            ("Review firewall rules",        False),
            ("Update Defender signatures",   False),
            ("Enable 2FA",                   True),
            ("Check breach database",        False),
        ]
        for item, done in checklist:
            row = tk.Frame(chk_inner, bg=T["BG_CARD"]); row.pack(fill=tk.X, pady=2)
            color = T["GREEN"] if done else T["TEXT_DIM"]
            icon  = "✓" if done else "○"
            tk.Label(row, text=icon, font=("Consolas",10,"bold"),
                     bg=T["BG_CARD"], fg=color, width=2).pack(side=tk.LEFT)
            tk.Label(row, text=item, font=("Consolas",8),
                     bg=T["BG_CARD"], fg=color if done else T["TEXT_MID"],
                     anchor="w").pack(side=tk.LEFT)

        # Live traffic card
        traffic_card = tk.Frame(right, bg=T["BG_CARD"])
        traffic_card.pack(fill=tk.X, padx=8, pady=4)
        tk.Frame(traffic_card, bg=T["CYAN"], height=3).pack(fill=tk.X)
        tc_inner = tk.Frame(traffic_card, bg=T["BG_CARD"], padx=14, pady=10)
        tc_inner.pack(fill=tk.X)
        tk.Label(tc_inner, text="📶 LIVE TRAFFIC",
                 font=("Consolas",9,"bold"), bg=T["BG_CARD"],
                 fg=T["CYAN"]).pack(anchor="w", pady=(0,6))
        self._dash_sent = tk.Label(tc_inner, text="↑ -- KB/s",
                                    font=("Consolas",12,"bold"),
                                    bg=T["BG_CARD"], fg=T["GREEN"])
        self._dash_sent.pack(anchor="w")
        self._dash_recv = tk.Label(tc_inner, text="↓ -- KB/s",
                                    font=("Consolas",12,"bold"),
                                    bg=T["BG_CARD"], fg=T["CYAN"])
        self._dash_recv.pack(anchor="w")

        # Theme switcher
        theme_card = tk.Frame(right, bg=T["BG_CARD"])
        theme_card.pack(fill=tk.X, padx=8, pady=4)
        tk.Frame(theme_card, bg="#AA44FF", height=3).pack(fill=tk.X)
        th_inner = tk.Frame(theme_card, bg=T["BG_CARD"], padx=14, pady=10)
        th_inner.pack(fill=tk.X)
        tk.Label(th_inner, text="🎨 THEMES",
                 font=("Consolas",9,"bold"), bg=T["BG_CARD"],
                 fg="#AA44FF").pack(anchor="w", pady=(0,8))
        themes_row1 = tk.Frame(th_inner, bg=T["BG_CARD"]); themes_row1.pack(fill=tk.X)
        themes_row2 = tk.Frame(th_inner, bg=T["BG_CARD"]); themes_row2.pack(fill=tk.X, pady=(4,0))
        theme_btns = [
            ("🌙 DARK",   "dark",   T["CYAN"]),
            ("☀ DAY",    "day",    "#FFD60A"),
            ("🌙 NIGHT",  "night",  "#00FF41"),
            ("🔮 PURPLE", "purple", "#BB86FC"),
            ("💻 MATRIX", "matrix", "#00FF41"),
            ("🌊 OCEAN",  "ocean",  "#00E5FF"),
        ]
        for i, (label, theme, color) in enumerate(theme_btns):
            row_frame = themes_row1 if i < 3 else themes_row2
            tk.Button(row_frame, text=label,
                     font=("Consolas",7,"bold"),
                     bg=T["BG_ELEVATED"], fg=color,
                     relief=tk.FLAT, cursor="hand2",
                     padx=6, pady=4,
                     command=lambda t=theme: self._toggle_theme(t)
                     ).pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)

        # AI Agent quick chat
        ai_card = tk.Frame(right, bg=T["BG_CARD"])
        ai_card.pack(fill=tk.BOTH, expand=True, padx=8, pady=(4,8))
        tk.Frame(ai_card, bg="#AA44FF", height=3).pack(fill=tk.X)
        ai_inner = tk.Frame(ai_card, bg=T["BG_CARD"], padx=14, pady=10)
        ai_inner.pack(fill=tk.BOTH, expand=True)
        tk.Label(ai_inner, text="🤖 AI SECURITY AGENT",
                 font=("Consolas",9,"bold"), bg=T["BG_CARD"],
                 fg="#AA44FF").pack(anchor="w")
        tk.Label(ai_inner,
                 text="Ask anything about cybersecurity, scans, or get recommendations:",
                 font=("Segoe UI",8), bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                 wraplength=240, justify="left").pack(anchor="w", pady=4)
        quick_frame = tk.Frame(ai_inner, bg=T["BG_CARD"]); quick_frame.pack(fill=tk.X, pady=4)
        for q in ["What is VPN?", "Explain ransomware", "How to secure WiFi?"]:
            tk.Button(quick_frame, text=q, font=("Segoe UI",7),
                     bg=T["BG_ELEVATED"], fg="#AA44FF", relief=tk.FLAT,
                     cursor="hand2", padx=4, pady=2,
                     command=lambda _q=q: _go_tab("AI CHAT")
                     ).pack(fill=tk.X, pady=1)
        tk.Button(ai_inner, text="💬 OPEN AI CHAT →",
                  font=("Consolas",9,"bold"),
                  bg="#AA44FF", fg="white", relief=tk.FLAT,
                  cursor="hand2", pady=6,
                  command=lambda: _go_tab("AI CHAT")).pack(fill=tk.X, pady=(6,0))

        self.after(600, self._dash_refresh)

    def _dash_update_traffic(self):
        """Called from traffic monitor callback."""
        try:
            data = getattr(self, "_dash_traffic_data", {})
            if not data: return
            sent = data.get("sent_rate", 0)
            recv = data.get("recv_rate", 0)
            self._dash_sent.configure(
                text=f"↑ {sent:.1f} KB/s",
                fg=T["GREEN"] if sent < 100 else T["ORANGE"])
            self._dash_recv.configure(
                text=f"↓ {recv:.1f} KB/s",
                fg=T["CYAN"] if recv < 100 else T["YELLOW"])
        except Exception:
            pass


    def _tab_timeline(self, parent):
        tk.Label(parent, text="  ◈  VULNERABILITY TIMELINE — CALENDAR VIEW",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Har din ke scans calendar mein — rang se risk level pata chalti hai",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["CYAN"], height=2).pack(fill=tk.X)

        now = datetime.now()
        self._cal_year  = tk.IntVar(value=now.year)
        self._cal_month = tk.IntVar(value=now.month)

        # Nav bar
        nav = tk.Frame(parent, bg=T["BG_CARD"], padx=10, pady=8); nav.pack(fill=tk.X)
        tk.Button(nav, text="◀", font=("Consolas",12), bg=T["BG_ELEVATED"],
                  fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=10, pady=4,
                  command=self._cal_prev).pack(side=tk.LEFT)
        self.cal_title = tk.Label(nav, text="", font=("Consolas",12,"bold"),
                                   bg=T["BG_CARD"], fg=T["CYAN"])
        self.cal_title.pack(side=tk.LEFT, padx=20)
        tk.Button(nav, text="▶", font=("Consolas",12), bg=T["BG_ELEVATED"],
                  fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=10, pady=4,
                  command=self._cal_next).pack(side=tk.LEFT)
        tk.Button(nav, text="TODAY", font=("Consolas",9), bg=T["CYAN"],
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=10, pady=4,
                  command=self._cal_today).pack(side=tk.LEFT, padx=14)
        # Legend
        for label, color in [("LOW",T["GREEN"]),("MEDIUM",T["YELLOW"]),("HIGH",T["ORANGE"]),("CRITICAL",T["RED"])]:
            tk.Label(nav, text=f"  ■ {label}", font=("Consolas",8,"bold"),
                     bg=T["BG_CARD"], fg=color).pack(side=tk.RIGHT)

        content = tk.Frame(parent, bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH, expand=True)

        # Calendar canvas
        self.cal_canvas = tk.Canvas(content, bg="#020609", highlightthickness=0)
        self.cal_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.cal_canvas.bind("<Configure>", lambda e: self._cal_draw())

        # Detail panel
        detail = tk.Frame(content, bg=T["BG_CARD"], width=240)
        detail.pack(side=tk.LEFT, fill=tk.Y, padx=(0,4), pady=4)
        detail.pack_propagate(False)
        tk.Frame(detail, bg=T["CYAN"], height=2).pack(fill=tk.X)
        tk.Label(detail, text="  CLICK A DAY", font=("Consolas",8,"bold"),
                 bg=T["BG_CARD"], fg=T["CYAN"], anchor="w", pady=4).pack(fill=tk.X)
        self.cal_detail = tk.Text(detail, font=("Consolas",8), bg=T["LOG_BG"],
                                   fg=T["TEXT_MID"], relief=tk.FLAT, padx=8, pady=6,
                                   state=tk.DISABLED, wrap=tk.WORD)
        self.cal_detail.pack(fill=tk.BOTH, expand=True)
        self.cal_detail.tag_configure("h",  foreground=T["CYAN"],   font=("Consolas",9,"bold"))
        self.cal_detail.tag_configure("crit",foreground=T["RED"],   font=("Consolas",8,"bold"))
        self.cal_detail.tag_configure("high",foreground=T["ORANGE"])
        self.cal_detail.tag_configure("med", foreground=T["YELLOW"])
        self.cal_detail.tag_configure("low", foreground=T["GREEN"])
        self._cal_draw()

    def _cal_prev(self):
        m = self._cal_month.get() - 1
        y = self._cal_year.get()
        if m < 1: m = 12; y -= 1
        self._cal_month.set(m); self._cal_year.set(y); self._cal_draw()

    def _cal_next(self):
        m = self._cal_month.get() + 1
        y = self._cal_year.get()
        if m > 12: m = 1; y += 1
        self._cal_month.set(m); self._cal_year.set(y); self._cal_draw()

    def _cal_today(self):
        now = datetime.now()
        self._cal_month.set(now.month); self._cal_year.set(now.year); self._cal_draw()

    def _cal_draw(self):
        import calendar as cal_mod
        y = self._cal_year.get(); m = self._cal_month.get()
        self.cal_title.configure(text=f"{cal_mod.month_name[m]}  {y}")
        W = self.cal_canvas.winfo_width() or 600
        H = self.cal_canvas.winfo_height() or 400
        draw_calendar(self.cal_canvas, y, m, W, H,
                      bg=T["LOG_BG"], on_click=self._cal_day_click)

    def _cal_day_click(self, day, entries):
        self.cal_detail.configure(state=tk.NORMAL)
        self.cal_detail.delete(1.0, tk.END)
        self.cal_detail.insert(tk.END, f"DATE: {self._cal_year.get()}-{self._cal_month.get():02d}-{day:02d}\n", "h")
        self.cal_detail.insert(tk.END, f"{len(entries)} scan(s)\n\n", "h")
        for e in entries:
            lv  = e.get("level","LOW")
            tag = {"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low"}.get(lv,"low")
            self.cal_detail.insert(tk.END, f"[{e.get('time','')}] ", "h")
            self.cal_detail.insert(tk.END, f"Score: {e.get('score','?')}  Level: {lv}\n", tag)
            if e.get("target"):
                self.cal_detail.insert(tk.END, f"Target: {e['target']}\n", "")
            self.cal_detail.insert(tk.END, "\n")
        self.cal_detail.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: NETWORK TRAFFIC GRAPH
    # ══════════════════════════════════════════════════════════════════════

    def _tab_traffic(self, parent):
        tk.Label(parent, text="  ◈  LIVE NETWORK TRAFFIC GRAPH",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Real-time bytes sent/received — 60 second rolling window",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["CYAN"], height=2).pack(fill=tk.X)

        # Stats row
        stats = tk.Frame(parent, bg=T["BG_ELEVATED"], padx=12, pady=8); stats.pack(fill=tk.X)
        self.traffic_stat_vars = {}
        for key, label, color in [
            ("recv_kbs","DOWNLOAD","#00D4FF"),("sent_kbs","UPLOAD","#FF8C42"),
            ("total_recv","TOTAL DL","#00D4FF"),("total_sent","TOTAL UL","#FF8C42"),
        ]:
            card = tk.Frame(stats, bg=T["BG_CARD"]); card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            tk.Frame(card, bg=color, height=2).pack(fill=tk.X)
            var = tk.StringVar(value="-- KB/s")
            tk.Label(card, textvariable=var, font=("Consolas",14,"bold"),
                     bg=T["BG_CARD"], fg=color).pack(pady=(8,2))
            tk.Label(card, text=label, font=("Consolas",7,"bold"),
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(pady=(0,6))
            self.traffic_stat_vars[key] = var

        # Main graph canvas
        self.traffic_canvas = tk.Canvas(parent, bg="#020609", highlightthickness=0)
        self.traffic_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.traffic_canvas.bind("<Configure>", lambda e: self._traffic_redraw())
        self._traffic_data = {"recv_hist":[0]*60,"sent_hist":[0]*60}
        self._traffic_redraw()

    def _on_traffic_update_tab(self, data):
        self._traffic_data = data
        self._ui( self._traffic_redraw)
        self._ui( lambda: self._traffic_update_stats(data))

    def _traffic_redraw(self):
        if not hasattr(self,'traffic_canvas'): return
        td = getattr(self,'_traffic_data',{})
        W = self.traffic_canvas.winfo_width() or 800
        H = self.traffic_canvas.winfo_height() or 400
        draw_traffic_graph(self.traffic_canvas,
                           td.get("recv_hist",[0]*60),
                           td.get("sent_hist",[0]*60), W, H)

    def _traffic_update_stats(self, data):
        if not hasattr(self,'traffic_stat_vars'): return
        r = data.get("recv_kbs",0); s = data.get("sent_kbs",0)
        tr = data.get("total_recv",0); ts = data.get("total_sent",0)
        def fmt(v): return f"{v:.1f} KB/s" if v<1024 else f"{v/1024:.2f} MB/s"
        def fmtb(v): return f"{v/1024:.1f} KB" if v<1048576 else f"{v/1048576:.2f} MB"
        if "recv_kbs"   in self.traffic_stat_vars: self.traffic_stat_vars["recv_kbs"].set(fmt(r))
        if "sent_kbs"   in self.traffic_stat_vars: self.traffic_stat_vars["sent_kbs"].set(fmt(s))
        if "total_recv" in self.traffic_stat_vars: self.traffic_stat_vars["total_recv"].set(fmtb(tr))
        if "total_sent" in self.traffic_stat_vars: self.traffic_stat_vars["total_sent"].set(fmtb(ts))

    # ══════════════════════════════════════════════════════════════════════
    # TAB: DARK WEB MONITOR
    # ══════════════════════════════════════════════════════════════════════

    def _tab_darkweb(self, parent):
        tk.Label(parent, text="  ◈  DARK WEB KEYWORD MONITOR",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#AA44FF",
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Apne keywords monitor karo — paste sites aur leak forums mein",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg="#AA44FF", height=2).pack(fill=tk.X)

        content = tk.Frame(parent, bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH, expand=True)

        # Left: keywords management
        left = tk.Frame(content, bg=T["BG_PANEL"], width=260); left.pack(side=tk.LEFT, fill=tk.Y)
        left.pack_propagate(False)
        tk.Frame(left, bg="#AA44FF", height=2).pack(fill=tk.X)
        tk.Label(left, text="  MONITORED KEYWORDS", font=("Consolas",8,"bold"),
                 bg=T["BG_PANEL"], fg="#AA44FF", pady=6, anchor="w").pack(fill=tk.X)

        # Add keyword
        add_row = tk.Frame(left, bg=T["BG_PANEL"], padx=8, pady=6); add_row.pack(fill=tk.X)
        self.dw_kw_var = tk.StringVar()
        kf = tk.Frame(add_row, bg=T["CYAN_DIM"], padx=1, pady=1); kf.pack(fill=tk.X)
        kw_entry = tk.Entry(kf, textvariable=self.dw_kw_var, font=("Consolas",9),
                            bg=T["BG_CARD"], fg="#AA44FF", insertbackground="#AA44FF",
                            relief=tk.FLAT, bd=4)
        kw_entry.pack(fill=tk.X)
        kw_entry.bind("<Return>", lambda e: self._dw_add_kw())
        tk.Button(add_row, text="+ ADD", font=("Consolas",9,"bold"), bg="#AA44FF",
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=8, pady=4,
                  command=self._dw_add_kw).pack(fill=tk.X, pady=4)

        # Keywords list
        self.dw_kw_list = tk.Listbox(left, font=("Consolas",9), bg=T["BG_CARD"],
                                      fg="#AA44FF", selectbackground="#AA44FF",
                                      selectforeground=T["BG_DEEP"], relief=tk.FLAT,
                                      bd=0, activestyle="none")
        self.dw_kw_list.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        tk.Button(left, text="🗑 REMOVE SELECTED", font=("Consolas",8),
                  bg=T["BG_ELEVATED"], fg=T["TEXT_DIM"], relief=tk.FLAT, cursor="hand2",
                  pady=4, command=self._dw_remove_kw).pack(fill=tk.X, padx=6, pady=4)

        # Controls
        ctrl = tk.Frame(left, bg=T["BG_CARD"], padx=8, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔍 MANUAL CHECK", font=("Consolas",9,"bold"),
                  bg="#AA44FF", fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  pady=6, command=self._dw_manual_check).pack(fill=tk.X)
        self.dw_status_var = tk.StringVar(value="Monitoring: READY")
        tk.Label(ctrl, textvariable=self.dw_status_var, font=("Consolas",7),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(pady=4)

        # Right: alerts
        right = tk.Frame(content, bg=T["BG_DEEP"]); right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ah = tk.Frame(right, bg=T["BG_CARD"], padx=10, pady=6); ah.pack(fill=tk.X)
        tk.Label(ah, text="ALERTS", font=("Consolas",9,"bold"), bg=T["BG_CARD"],
                 fg="#AA44FF").pack(side=tk.LEFT)
        tk.Button(ah, text="🗑 CLEAR", font=("Consolas",8), bg=T["BG_ELEVATED"],
                  fg=T["TEXT_DIM"], relief=tk.FLAT, cursor="hand2", padx=6,
                  command=self._dw_clear_alerts).pack(side=tk.RIGHT)

        cols = ("Time","Source","Title","Keywords Matched","Severity")
        sty = ttk.Style()
        sty.configure("DW.Treeview", background=T["BG_CARD"], foreground=T["TEXT_MID"],
                       fieldbackground=T["BG_CARD"], rowheight=26, font=("Consolas",8))
        sty.configure("DW.Treeview.Heading", background=T["BG_ELEVATED"],
                       foreground="#AA44FF", font=("Consolas",8,"bold"))
        tf = tk.Frame(right, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.dw_tree = ttk.Treeview(tf, columns=cols, show="headings", style="DW.Treeview")
        for col, w in zip(cols, [100,120,200,180,80]):
            self.dw_tree.heading(col, text=col); self.dw_tree.column(col, width=w, anchor="w")
        for tag, fg in [("HIGH",T["ORANGE"]),("MEDIUM",T["YELLOW"]),("LOW",T["GREEN"])]:
            self.dw_tree.tag_configure(tag, foreground=fg)
        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.dw_tree.yview)
        self.dw_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.dw_tree.pack(fill=tk.BOTH, expand=True)

        self._dw_load_keywords()
        self._dw_load_alerts()

    def _dw_add_kw(self):
        kw = self.dw_kw_var.get().strip()
        if not kw: return
        if self._dw_monitor.add_keyword(kw):
            self.dw_kw_var.set("")
            self._dw_load_keywords()

    def _dw_remove_kw(self):
        sel = self.dw_kw_list.curselection()
        if not sel: return
        kw = self.dw_kw_list.get(sel[0])
        self._dw_monitor.remove_keyword(kw)
        self._dw_load_keywords()

    def _dw_load_keywords(self):
        self.dw_kw_list.delete(0, tk.END)
        for kw in self._dw_monitor.keywords:
            self.dw_kw_list.insert(tk.END, kw)

    def _dw_load_alerts(self):
        for r in self.dw_tree.get_children(): self.dw_tree.delete(r)
        for a in self._dw_monitor.get_alerts():
            kws = ", ".join(a.get("keywords",[]))[:40]
            self.dw_tree.insert("","end", values=(
                a.get("time",""), a.get("source",""), a.get("title","")[:40],
                kws, a.get("severity","?")), tags=(a.get("severity","LOW"),))

    def _dw_manual_check(self):
        self.dw_status_var.set("Checking...")
        threading.Thread(target=self._dw_check_bg, daemon=True).start()

    def _dw_check_bg(self):
        alerts = self._dw_monitor.manual_check()
        self._ui( lambda: (
            self._dw_load_alerts(),
            self.dw_status_var.set(f"Done — {len(alerts)} new alert(s) | "
                                    f"Last: {self._dw_monitor.stats['last_check']}")))

    def _on_dw_alert(self, alert):
        try:
            self._ui( lambda: self._dw_load_alerts())
        except RuntimeError:
            pass

    def _dw_clear_alerts(self):
        self._dw_monitor.clear_alerts(); self._dw_load_alerts()

    # ══════════════════════════════════════════════════════════════════════
    # TAB: CVE / EXPLOIT DATABASE SEARCH
    # ══════════════════════════════════════════════════════════════════════

    def _tab_cve(self, parent):
        tk.Label(parent, text="  ◈  CVE / EXPLOIT DATABASE SEARCH",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["RED"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  NVD (National Vulnerability Database) se CVEs search karo",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["RED"], height=2).pack(fill=tk.X)

        # Search bar
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=14, pady=10); ctrl.pack(fill=tk.X)
        self.cve_query = tk.StringVar()
        sf = tk.Frame(ctrl, bg=T["RED"], padx=1, pady=1); sf.pack(side=tk.LEFT, fill=tk.X, expand=True)
        cve_entry = tk.Entry(sf, textvariable=self.cve_query, font=("Consolas",12),
                             bg=T["BG_DEEP"], fg=T["RED"], insertbackground=T["RED"],
                             relief=tk.FLAT, bd=5)
        cve_entry.pack(fill=tk.X)
        cve_entry.bind("<Return>", lambda e: self._cve_search())
        tk.Button(ctrl, text="🔍 SEARCH", font=("Consolas",10,"bold"),
                  bg=T["RED"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=6, command=self._cve_search).pack(side=tk.LEFT, padx=8)
        tk.Button(ctrl, text="⚡ LATEST CRITICAL", font=("Consolas",9),
                  bg=T["BG_ELEVATED"], fg=T["RED"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=6, command=self._cve_latest).pack(side=tk.LEFT)

        # Quick searches
        quick = tk.Frame(parent, bg=T["BG_CARD"], padx=14, pady=4); quick.pack(fill=tk.X)
        tk.Label(quick, text="Quick:", font=("Consolas",8), bg=T["BG_CARD"],
                 fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,8))
        for q in ["Windows RDP","Log4j","SMB","Apache","OpenSSL","Exchange"]:
            tk.Button(quick, text=q, font=("Consolas",8), bg=T["BG_ELEVATED"],
                      fg=T["TEXT_MID"], relief=tk.FLAT, cursor="hand2", padx=6, pady=3,
                      command=lambda x=q:(self.cve_query.set(x),self._cve_search())
                      ).pack(side=tk.LEFT, padx=2)

        sty = ttk.Style()
        sty.configure("CVE.Treeview", background=T["BG_CARD"], foreground=T["TEXT_MID"],
                       fieldbackground=T["BG_CARD"], rowheight=28, font=("Consolas",8))
        sty.configure("CVE.Treeview.Heading", background=T["BG_ELEVATED"],
                       foreground=T["RED"], font=("Consolas",9,"bold"))
        tf = tk.Frame(parent, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        cols = ("CVE ID","CVSS","Severity","Published","Description")
        self.cve_tree = ttk.Treeview(tf, columns=cols, show="headings", style="CVE.Treeview")
        for col, w in zip(cols, [130,60,80,100,500]):
            self.cve_tree.heading(col, text=col); self.cve_tree.column(col, width=w, anchor="w")
        for sev, fg in [("CRITICAL",T["RED"]),("HIGH",T["ORANGE"]),("MEDIUM",T["YELLOW"]),("LOW",T["CYAN"])]:
            self.cve_tree.tag_configure(sev, foreground=fg)
        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.cve_tree.yview)
        self.cve_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.cve_tree.pack(fill=tk.BOTH, expand=True)

        self.cve_status = tk.StringVar(value="Search for CVEs above")
        tk.Label(parent, textvariable=self.cve_status, font=("Consolas",8),
                 bg=T["BG_ELEVATED"], fg=T["TEXT_DIM"], anchor="w", padx=12, pady=4).pack(fill=tk.X)

        self.cve_tree.bind("<<TreeviewSelect>>", self._cve_show_detail)
        self._cve_latest()  # Load on open

    def _cve_search(self):
        q = self.cve_query.get().strip()
        if not q: return
        self.cve_status.set("Searching NVD...")
        threading.Thread(target=lambda: self._ui( lambda: self._cve_show(search_nvd_api(q))), daemon=True).start()

    def _cve_latest(self):
        self.cve_status.set("Loading latest critical CVEs...")
        threading.Thread(target=lambda: self._ui( lambda: self._cve_show(get_latest_cves(15))), daemon=True).start()

    def _cve_show(self, cves):
        for r in self.cve_tree.get_children(): self.cve_tree.delete(r)
        for c in cves:
            sev = c.get("severity","NONE")
            self.cve_tree.insert("","end", values=(
                c["id"], c.get("score","?"), sev,
                c.get("published","?"), c.get("description","")[:120]),
                tags=(sev,))
        self.cve_status.set(f"{len(cves)} CVE(s) found | Source: NVD/Offline DB")

    def _cve_show_detail(self, event):
        sel = self.cve_tree.selection()
        if not sel: return

    # ══════════════════════════════════════════════════════════════════════
    # TAB: BACKUP & RESTORE
    # ══════════════════════════════════════════════════════════════════════

    def _tab_backup(self, parent):
        tk.Label(parent, text="  ◈  BACKUP & RESTORE SETTINGS",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["GREEN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Sari config files aur settings ka zip backup — restore bhi kar sako",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["GREEN"], height=2).pack(fill=tk.X)

        content = tk.Frame(parent, bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)

        # Create backup
        bc = tk.Frame(content, bg=T["BG_CARD"], padx=16, pady=14); bc.pack(fill=tk.X)
        tk.Frame(bc, bg=T["GREEN"], height=2).pack(fill=tk.X, pady=(0,10))
        tk.Label(bc, text="CREATE BACKUP", font=("Consolas",10,"bold"),
                 bg=T["BG_CARD"], fg=T["GREEN"], anchor="w").pack(fill=tk.X)
        br = tk.Frame(bc, bg=T["BG_CARD"]); br.pack(fill=tk.X, pady=6)
        tk.Label(br, text="Label (optional):", font=("Consolas",8), bg=T["BG_CARD"],
                 fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,6))
        self.backup_label = tk.StringVar()
        lf = tk.Frame(br, bg=T["CYAN_DIM"], padx=1, pady=1); lf.pack(side=tk.LEFT)
        tk.Entry(lf, textvariable=self.backup_label, font=("Consolas",10), width=20,
                 bg=T["BG_DEEP"], fg=T["GREEN"], insertbackground=T["GREEN"],
                 relief=tk.FLAT, bd=4).pack()
        tk.Button(br, text="💾 CREATE BACKUP NOW", font=("Consolas",10,"bold"),
                  bg=T["GREEN_DIM"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=6, command=self._do_backup).pack(side=tk.LEFT, padx=10)
        self.backup_result = tk.Label(bc, text="", font=("Consolas",8),
                                       bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.backup_result.pack(anchor="w")

        # Settings panel
        settings_card = tk.Frame(content, bg=T["BG_CARD"], padx=16, pady=14); settings_card.pack(fill=tk.X, pady=(12,0))
        tk.Frame(settings_card, bg="#AA44FF", height=2).pack(fill=tk.X, pady=(0,10))
        tk.Label(settings_card, text="APP SETTINGS", font=("Consolas",10,"bold"),
                 bg=T["BG_CARD"], fg="#AA44FF", anchor="w").pack(fill=tk.X)
        sets_row = tk.Frame(settings_card, bg=T["BG_CARD"]); sets_row.pack(fill=tk.X, pady=6)
        # Font size
        tk.Label(sets_row, text="Font Size:", font=("Consolas",8), bg=T["BG_CARD"],
                 fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,6))
        self.font_size_var = tk.IntVar(value=getattr(self,"_font_size",10))
        for sz in [8, 9, 10, 11, 12]:
            tk.Radiobutton(sets_row, text=str(sz), variable=self.font_size_var, value=sz,
                           font=("Consolas",9), bg=T["BG_CARD"], fg="#AA44FF",
                           selectcolor=T["BG_ELEVATED"], activebackground=T["BG_CARD"],
                           command=self._apply_font_size).pack(side=tk.LEFT, padx=4)
        # Theme picker
        theme_row = tk.Frame(settings_card, bg=T["BG_CARD"]); theme_row.pack(fill=tk.X, pady=4)
        tk.Label(theme_row, text="Theme:", font=("Consolas",8), bg=T["BG_CARD"],
                 fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,8))
        for theme, color, label in [
            ("dark","#3A6080","🌙 Dark"),("light","#CCCCCC","☀ Light"),
            ("purple","#BB86FC","🔮 Purple"),("matrix","#00FF41","💻 Matrix"),
            ("ocean","#00E5FF","🌊 Ocean")]:
            tk.Button(theme_row, text=label, font=("Consolas",8,"bold"),
                      bg=T["BG_ELEVATED"], fg=color, relief=tk.FLAT, cursor="hand2",
                      padx=8, pady=4,
                      command=lambda t=theme: self._toggle_theme(t)).pack(side=tk.LEFT, padx=3)

        # Backups list
        bl = tk.Frame(content, bg=T["BG_CARD"], padx=16, pady=14); bl.pack(fill=tk.BOTH, expand=True, pady=(12,0))
        tk.Frame(bl, bg=T["CYAN"], height=2).pack(fill=tk.X, pady=(0,8))
        bh = tk.Frame(bl, bg=T["BG_CARD"]); bh.pack(fill=tk.X)
        tk.Label(bh, text="SAVED BACKUPS", font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"], fg=T["CYAN"], anchor="w").pack(side=tk.LEFT)
        tk.Button(bh, text="🔄 REFRESH", font=("Consolas",8), bg=T["BG_ELEVATED"],
                  fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=6,
                  command=self._backup_load_list).pack(side=tk.RIGHT)

        cols = ("Filename","Created","Files","Size KB")
        sty = ttk.Style()
        sty.configure("Bk.Treeview", background=T["BG_ELEVATED"], foreground=T["TEXT_MID"],
                       fieldbackground=T["BG_ELEVATED"], rowheight=24, font=("Consolas",8))
        sty.configure("Bk.Treeview.Heading", background=T["BG_CARD"],
                       foreground=T["GREEN"], font=("Consolas",8,"bold"))
        btf = tk.Frame(bl, bg=T["BG_DEEP"]); btf.pack(fill=tk.BOTH, expand=True, pady=4)
        self.backup_tree = ttk.Treeview(btf, columns=cols, show="headings",
                                         style="Bk.Treeview", height=5)
        for col, w in zip(cols, [280,160,60,80]):
            self.backup_tree.heading(col, text=col); self.backup_tree.column(col, width=w, anchor="w")
        bvsb = ttk.Scrollbar(btf, orient=tk.VERTICAL, command=self.backup_tree.yview)
        self.backup_tree.configure(yscrollcommand=bvsb.set); bvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.backup_tree.pack(fill=tk.BOTH, expand=True)

        btn_row = tk.Frame(bl, bg=T["BG_CARD"]); btn_row.pack(fill=tk.X, pady=4)
        tk.Button(btn_row, text="⟳ RESTORE SELECTED", font=("Consolas",9,"bold"),
                  bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=12, pady=5, command=self._do_restore).pack(side=tk.LEFT)
        tk.Button(btn_row, text="🗑 DELETE", font=("Consolas",8),
                  bg="#3A0A0A", fg=T["RED"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=5, command=self._do_delete_backup).pack(side=tk.LEFT, padx=8)
        self._backup_load_list()

    def _do_backup(self):
        try:
            path, size = create_backup(self.backup_label.get())
            self.backup_result.configure(
                text=f"✓ Backup created: {os.path.basename(path)}  ({size} KB)", fg=T["GREEN"])
            self._backup_load_list()
        except Exception as e:
            self.backup_result.configure(text=f"Error: {e}", fg=T["RED"])

    def _backup_load_list(self):
        for r in self.backup_tree.get_children(): self.backup_tree.delete(r)
        for b in list_backups():
            self.backup_tree.insert("","end", values=(
                b["filename"], b["created"], b["files"], b["size_kb"]),
                iid=b["path"])

    def _do_restore(self):
        sel = self.backup_tree.selection()
        if not sel: messagebox.showwarning("Select","Select a backup first"); return
        if messagebox.askyesno("Restore","Restore this backup? Current settings will be overwritten."):
            ok, msg = restore_backup(sel[0])
            messagebox.showinfo("Restore", msg) if ok else messagebox.showerror("Error", msg)

    def _do_delete_backup(self):
        sel = self.backup_tree.selection()
        if not sel: return
        if messagebox.askyesno("Delete","Delete this backup?"):
            delete_backup(sel[0]); self._backup_load_list()

    def _apply_font_size(self):
        sz = self.font_size_var.get()
        self._font_size = sz
        try: save_app_settings({"theme":self.current_theme,"language":self.current_lang,"font_size":sz})
        except Exception: pass
        messagebox.showinfo("Font Size",f"Font size set to {sz}pt\nRestart app to apply fully.")


    
    # ══════════════════════════════════════════════════════════════════════
    # TAB: WIFI SAVED PASSWORDS
    # ══════════════════════════════════════════════════════════════════════
    def _tab_wifi_pw(self, parent):
        tk.Label(parent, text="  ◈  SAVED WiFi PASSWORDS",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Apne device pe saved WiFi networks ke passwords dekho (netsh wlan)",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["CYAN"], height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔑 SHOW SAVED PASSWORDS", font=("Consolas",10,"bold"),
                  bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=16, pady=7, command=self._wifi_pw_load).pack(side=tk.LEFT)
        self.wifi_pw_status = tk.Label(ctrl, text="Click button to load", font=("Consolas",9),
                                        bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.wifi_pw_status.pack(side=tk.LEFT, padx=14)
        tk.Button(ctrl, text="📋 COPY", font=("Consolas",9), bg=T["BG_ELEVATED"],
                  fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=8, pady=7,
                  command=self._wifi_pw_copy).pack(side=tk.RIGHT)
        cols = ("WiFi Name (SSID)", "Password", "Security", "Has Password")
        tf = tk.Frame(parent, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.wifi_pw_tree = ttk.Treeview(tf, columns=cols, show="headings")
        self.wifi_pw_tree.tag_configure("has_pw", foreground=T["GREEN"])
        self.wifi_pw_tree.tag_configure("no_pw",  foreground=T["TEXT_DIM"])
        for col, w in zip(cols, [220,220,130,100]):
            self.wifi_pw_tree.heading(col, text=col)
            self.wifi_pw_tree.column(col, width=w, anchor="w")
        vsb = ttk.Scrollbar(tf, orient=tk.VERTICAL, command=self.wifi_pw_tree.yview)
        self.wifi_pw_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y); self.wifi_pw_tree.pack(fill=tk.BOTH, expand=True)
        tk.Label(parent, text="ℹ  Sirf apne saved networks — Run as Administrator for full access",
                 font=("Segoe UI",8), bg=T["BG_ELEVATED"], fg=T["TEXT_DIM"],
                 anchor="w", padx=12, pady=5).pack(fill=tk.X)

    def _wifi_pw_load(self):
        self.wifi_pw_status.configure(text="Loading...")
        threading.Thread(target=self._wifi_pw_bg, daemon=True).start()
    def _wifi_pw_bg(self):
        results = get_wifi_passwords()
        self._ui( lambda: self._wifi_pw_show(results))
    def _wifi_pw_show(self, results):
        for r in self.wifi_pw_tree.get_children(): self.wifi_pw_tree.delete(r)
        for n in results:
            tag = "has_pw" if n["has_pw"] else "no_pw"
            self.wifi_pw_tree.insert("","end", values=(
                n["ssid"], n["password"], n["auth"],
                "✓ YES" if n["has_pw"] else "— Open"), tags=(tag,))
        self.wifi_pw_status.configure(
            text=f"✓ {len(results)} networks | {sum(1 for n in results if n['has_pw'])} with passwords")
    def _wifi_pw_copy(self):
        sel = self.wifi_pw_tree.selection()
        if not sel: return
        v = self.wifi_pw_tree.item(sel[0])["values"]
        self.clipboard_clear(); self.clipboard_append(f"SSID: {v[0]}\nPassword: {v[1]}")

    # ══════════════════════════════════════════════════════════════════════
    # TAB: VPN STATUS CHECKER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_vpn(self, parent):
        tk.Label(parent, text="  ◈  VPN STATUS CHECKER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["GREEN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Frame(parent, bg=T["GREEN"], height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔍 CHECK VPN STATUS", font=("Consolas",10,"bold"),
                  bg=T["GREEN_DIM"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=16, pady=7, command=self._vpn_check).pack(side=tk.LEFT)
        sf = tk.Frame(parent, bg=T["BG_DEEP"]); sf.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        left = tk.Frame(sf, bg=T["BG_CARD"], padx=20, pady=20, width=300)
        left.pack(side=tk.LEFT, fill=tk.Y); left.pack_propagate(False)
        tk.Frame(left, bg=T["GREEN"], height=3).pack(fill=tk.X, pady=(0,12))
        self.vpn_icon = tk.Label(left, text="?", font=("Segoe UI",60), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.vpn_icon.pack()
        self.vpn_status_lbl = tk.Label(left, text="Not checked", font=("Consolas",12,"bold"),
                                        bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.vpn_status_lbl.pack(pady=8)
        self.vpn_ip_lbl   = tk.Label(left, text="Public IP: --", font=("Consolas",9), bg=T["BG_CARD"], fg=T["TEXT_MID"])
        self.vpn_ip_lbl.pack(anchor="w")
        self.vpn_risk_lbl = tk.Label(left, text="Risk: --", font=("Consolas",9,"bold"), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.vpn_risk_lbl.pack(anchor="w", pady=4)
        right = tk.Frame(sf, bg=T["BG_DEEP"]); right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,0))
        self.vpn_detail = tk.Text(right, font=("Consolas",9), bg=T["LOG_BG"], fg=T["TEXT_MID"],
                                   relief=tk.FLAT, padx=10, pady=8, state=tk.DISABLED, wrap=tk.WORD)
        self.vpn_detail.pack(fill=tk.BOTH, expand=True)
        self.vpn_detail.tag_configure("good", foreground=T["GREEN"])
        self.vpn_detail.tag_configure("warn", foreground=T["ORANGE"])
        self.vpn_detail.tag_configure("head", foreground=T["CYAN"], font=("Consolas",9,"bold"))

    def _vpn_check(self):
        self.vpn_status_lbl.configure(text="Checking...", fg=T["TEXT_DIM"])
        threading.Thread(target=lambda: self._ui( lambda: self._vpn_show(check_vpn_status())), daemon=True).start()
    def _vpn_show(self, r):
        active = r.get("active", False)
        self.vpn_icon.configure(text="🔒" if active else "🔓", fg=T["GREEN"] if active else T["ORANGE"])
        self.vpn_status_lbl.configure(text=r.get("status","--"), fg=T["GREEN"] if active else T["ORANGE"])
        self.vpn_ip_lbl.configure(text=f"Public IP: {r.get('public_ip','--')}")
        rc = {"LOW":T["GREEN"],"MEDIUM":T["YELLOW"],"HIGH":T["ORANGE"]}.get(r.get("risk",""), T["TEXT_DIM"])
        self.vpn_risk_lbl.configure(text=f"Risk: {r.get('risk','--')}", fg=rc)
        self.vpn_detail.configure(state=tk.NORMAL); self.vpn_detail.delete(1.0, tk.END)
        self.vpn_detail.insert(tk.END, f"Checked: {r.get('checked_at','')}\n\n", "head")
        if r.get("processes"):
            self.vpn_detail.insert(tk.END, "VPN Processes:\n", "head")
            for p in r["processes"]: self.vpn_detail.insert(tk.END, f"  ✓ {p}\n", "good")
        if not active:
            self.vpn_detail.insert(tk.END, "\n⚠ No VPN detected!\nUse ProtonVPN/Mullvad/NordVPN for privacy.", "warn")
        self.vpn_detail.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: PHISHING URL ANALYZER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_phishing(self, parent):
        tk.Label(parent, text="  ◈  PHISHING URL ANALYZER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["ORANGE"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  URL analyze karo — phishing indicators check karo",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["ORANGE"], height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=10); ctrl.pack(fill=tk.X)
        self.phish_url = tk.StringVar()
        uf = tk.Frame(ctrl, bg=T["ORANGE"], padx=1, pady=1); uf.pack(side=tk.LEFT, fill=tk.X, expand=True)
        e = tk.Entry(uf, textvariable=self.phish_url, font=("Consolas",11),
                     bg=T["BG_DEEP"], fg=T["ORANGE"], insertbackground=T["ORANGE"],
                     relief=tk.FLAT, bd=5); e.pack(fill=tk.X)
        e.bind("<Return>", lambda ev: self._phish_check())
        tk.Button(ctrl, text="🔍 ANALYZE", font=("Consolas",10,"bold"), bg=T["ORANGE"],
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=14, pady=6,
                  command=self._phish_check).pack(side=tk.LEFT, padx=8)
        quick = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=4); quick.pack(fill=tk.X)
        tk.Label(quick, text="Test:", font=("Consolas",8), bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,6))
        for u in ["paypal-secure.tk","http://192.168.1.1/login","https://google.com"]:
            tk.Button(quick, text=u, font=("Consolas",7), bg=T["BG_ELEVATED"], fg=T["TEXT_MID"],
                      relief=tk.FLAT, cursor="hand2", padx=5, pady=2,
                      command=lambda x=u:(self.phish_url.set(x),self._phish_check())).pack(side=tk.LEFT, padx=2)
        content = tk.Frame(parent, bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        gauge = tk.Frame(content, bg=T["BG_CARD"], width=230); gauge.pack(side=tk.LEFT, fill=tk.Y); gauge.pack_propagate(False)
        self.phish_score_canvas = tk.Canvas(gauge, bg=T["BG_CARD"], width=210, height=210, highlightthickness=0)
        self.phish_score_canvas.pack(pady=8)
        self.phish_verdict  = tk.Label(gauge, text="Enter URL above", font=("Consolas",9,"bold"),
                                        bg=T["BG_CARD"], fg=T["TEXT_DIM"], wraplength=190, justify="center")
        self.phish_verdict.pack(pady=4, padx=6)
        self.phish_domain_lbl = tk.Label(gauge, text="", font=("Consolas",8), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.phish_domain_lbl.pack()
        right = tk.Frame(content, bg=T["BG_DEEP"]); right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10,0))
        tk.Label(right, text="ANALYSIS FLAGS:", font=("Consolas",9,"bold"), bg=T["BG_DEEP"], fg=T["ORANGE"], anchor="w").pack(fill=tk.X)
        self.phish_flags = tk.Text(right, font=("Consolas",10), bg=T["LOG_BG"], fg=T["TEXT_MID"],
                                    relief=tk.FLAT, padx=10, pady=8, state=tk.DISABLED, wrap=tk.WORD)
        self.phish_flags.pack(fill=tk.BOTH, expand=True)
        self.phish_flags.tag_configure("crit", foreground=T["RED"],   font=("Consolas",10,"bold"))
        self.phish_flags.tag_configure("warn", foreground=T["ORANGE"])
        self.phish_flags.tag_configure("good", foreground=T["GREEN"])
        self.phish_flags.tag_configure("head", foreground=T["CYAN"],  font=("Consolas",10,"bold"))

    def _phish_check(self):
        url = self.phish_url.get().strip()
        if not url: return
        self._phish_show(analyze_url(url))
    def _phish_show(self, r):
        score = r.get("score",0)
        level = r.get("level","LOW")
        color = {"CRITICAL":T["RED"],"HIGH":T["ORANGE"],"MEDIUM":T["YELLOW"],"LOW":T["GREEN"]}.get(level,T["TEXT_DIM"])
        c = self.phish_score_canvas; c.delete("all")
        cx,cy,rad = 105,105,80
        c.create_oval(cx-rad,cy-rad,cx+rad,cy+rad, outline=T["BG_ELEVATED"], width=12)
        if score>0: c.create_arc(cx-rad,cy-rad,cx+rad,cy+rad, start=90, extent=-int(score*2.7), outline=color, width=12, style="arc")
        c.create_text(cx,cy-8,  text=str(score),  font=("Consolas",30,"bold"), fill=color)
        c.create_text(cx,cy+18, text="/100",       font=("Consolas",9),        fill=T["TEXT_DIM"])
        c.create_text(cx,cy+36, text=level,        font=("Consolas",9,"bold"), fill=color)
        self.phish_verdict.configure(text=r.get("verdict","--"), fg=color)
        self.phish_domain_lbl.configure(text=r.get("domain","")[:35])
        self.phish_flags.configure(state=tk.NORMAL); self.phish_flags.delete(1.0,tk.END)
        self.phish_flags.insert(tk.END, f"URL: {r.get('url','')[:80]}\n\n", "head")
        for flag in r.get("flags",[]):
            tag = "crit" if "🚨" in flag else "warn" if "⚠" in flag else "good"
            self.phish_flags.insert(tk.END, f"{flag}\n", tag)
        self.phish_flags.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: RANSOMWARE FILE MONITOR
    # ══════════════════════════════════════════════════════════════════════
    def _tab_ransomware(self, parent):
        tk.Label(parent, text="  ◈  RANSOMWARE FILE MONITOR",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["RED"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Encrypted files aur ransom notes detect karo",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["RED"], height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        self.ransom_path = tk.StringVar(value=os.path.expanduser("~\\Documents"))
        pf = tk.Frame(ctrl, bg=T["RED"], padx=1, pady=1); pf.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Entry(pf, textvariable=self.ransom_path, font=("Consolas",10),
                 bg=T["BG_DEEP"], fg=T["RED"], insertbackground=T["RED"],
                 relief=tk.FLAT, bd=5).pack(fill=tk.X)
        tk.Button(ctrl, text="📂", font=("Consolas",10), bg=T["BG_ELEVATED"], fg=T["RED"],
                  relief=tk.FLAT, cursor="hand2", padx=8,
                  command=lambda: self.ransom_path.set(filedialog.askdirectory() or self.ransom_path.get())
                  ).pack(side=tk.LEFT, padx=4)
        self.btn_ransom = tk.Button(ctrl, text="🔍 SCAN FOR RANSOMWARE",
                                     font=("Consolas",10,"bold"), bg=T["RED"], fg=T["BG_DEEP"],
                                     relief=tk.FLAT, cursor="hand2", padx=14, pady=6,
                                     command=self._ransom_scan)
        self.btn_ransom.pack(side=tk.LEFT, padx=6)
        self.ransom_verdict = tk.Label(parent, text="Select folder and click SCAN",
                                        font=("Consolas",10,"bold"), bg=T["BG_ELEVATED"],
                                        fg=T["TEXT_DIM"], anchor="w", padx=14, pady=8)
        self.ransom_verdict.pack(fill=tk.X)
        tf = tk.Frame(parent, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        cols = ("Type","Severity","File","Detail")
        self.ransom_tree = ttk.Treeview(tf, columns=cols, show="headings")
        for col,w in zip(cols,[130,80,300,300]):
            self.ransom_tree.heading(col,text=col); self.ransom_tree.column(col,width=w,anchor="w")
        self.ransom_tree.tag_configure("CRITICAL",foreground=T["RED"])
        self.ransom_tree.tag_configure("LOW",     foreground=T["GREEN"])
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.ransom_tree.yview)
        self.ransom_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.ransom_tree.pack(fill=tk.BOTH,expand=True)

    def _ransom_scan(self):
        self.btn_ransom.configure(state=tk.DISABLED, text="◉ SCANNING...")
        for r in self.ransom_tree.get_children(): self.ransom_tree.delete(r)
        threading.Thread(target=self._ransom_bg, daemon=True).start()
    def _ransom_bg(self):
        result = scan_ransomware_indicators(
            self.ransom_path.get(),
            progress_cb=lambda m: self._ui( lambda msg=m: self.ransom_verdict.configure(text=msg)))
        self._ui( lambda: self._ransom_show(result))
    def _ransom_show(self, r):
        self.btn_ransom.configure(state=tk.NORMAL, text="🔍 SCAN FOR RANSOMWARE")
        vc = {"CRITICAL":T["RED"],"HIGH":T["ORANGE"],"LOW":T["GREEN"]}.get(r["risk"],T["TEXT_DIM"])
        self.ransom_verdict.configure(
            text=f"{r['verdict']}  |  Files: {r['total_scanned']}  |  Encrypted: {r['encrypted_files']}  |  Notes: {r['ransom_notes']}",
            fg=vc)
        for h in r.get("hits",[]):
            sev = h.get("severity","LOW")
            self.ransom_tree.insert("","end",values=(h.get("type","?"),sev,
                os.path.basename(h.get("path","?"))[:50],h.get("detail","")[:60]),tags=(sev,))
        if not r.get("hits"):
            self.ransom_tree.insert("","end",values=("✓","LOW","No threats","Clean scan"),tags=("LOW",))

    # ══════════════════════════════════════════════════════════════════════
    # TAB: ROGUE AP DETECTOR
    # ══════════════════════════════════════════════════════════════════════
    def _tab_rogue_ap(self, parent):
        tk.Label(parent, text="  ◈  ROGUE AP / EVIL TWIN DETECTOR",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#FF44AA",
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Same SSID different BSSID = Evil Twin — WEP/Open networks detect karo",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg="#FF44AA", height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="📡 SCAN FOR ROGUE APs", font=("Consolas",10,"bold"),
                  bg="#FF44AA", fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=16, pady=7, command=self._rogue_scan).pack(side=tk.LEFT)
        self.rogue_status = tk.Label(ctrl, text="", font=("Consolas",9), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.rogue_status.pack(side=tk.LEFT, padx=12)
        self.rogue_verdict = tk.Label(parent, text="Click SCAN to start",
                                       font=("Consolas",10,"bold"), bg=T["BG_ELEVATED"],
                                       fg=T["TEXT_DIM"], anchor="w", padx=14, pady=8)
        self.rogue_verdict.pack(fill=tk.X)
        tf = tk.Frame(parent, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        cols = ("Alert Type","Severity","SSID","Detail","BSSIDs")
        self.rogue_tree = ttk.Treeview(tf, columns=cols, show="headings")
        for col,w in zip(cols,[130,80,150,280,180]):
            self.rogue_tree.heading(col,text=col); self.rogue_tree.column(col,width=w,anchor="w")
        self.rogue_tree.tag_configure("HIGH",     foreground=T["ORANGE"])
        self.rogue_tree.tag_configure("CRITICAL", foreground=T["RED"])
        self.rogue_tree.tag_configure("LOW",      foreground=T["GREEN"])
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.rogue_tree.yview)
        self.rogue_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.rogue_tree.pack(fill=tk.BOTH,expand=True)

    def _rogue_scan(self):
        self.rogue_status.configure(text="Scanning...")
        threading.Thread(target=lambda: self._ui( lambda: self._rogue_show(detect_rogue_ap())), daemon=True).start()
    def _rogue_show(self, r):
        self.rogue_status.configure(text=f"{r['total_networks']} networks scanned")
        for row in self.rogue_tree.get_children(): self.rogue_tree.delete(row)
        color = T["RED"] if r["risk"]=="CRITICAL" else T["ORANGE"] if r["risk"]=="HIGH" else T["GREEN"]
        self.rogue_verdict.configure(
            text=f"Networks: {r['total_networks']}  |  Alerts: {len(r['alerts'])}  |  Evil Twins: {r['evil_twin_count']}",
            fg=color)
        for a in r.get("alerts",[]):
            sev = a.get("severity","LOW")
            self.rogue_tree.insert("","end",values=(a["type"],sev,a["ssid"],
                a["detail"][:60],", ".join(a.get("bssids",[]))[:50]),tags=(sev,))
        if not r.get("alerts"):
            self.rogue_tree.insert("","end",values=("✓","LOW","None","No rogue APs detected",""),tags=("LOW",))

    # ══════════════════════════════════════════════════════════════════════
    # TAB: KEYLOGGER SCANNER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_keylogger(self, parent):
        tk.Label(parent, text="  ◈  KEYLOGGER ACTIVITY SCANNER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["YELLOW"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Processes, registry, startup mein keylogger indicators scan karo",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["YELLOW"], height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔍 SCAN FOR KEYLOGGERS", font=("Consolas",10,"bold"),
                  bg=T["YELLOW"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=16, pady=7, command=self._kl_scan).pack(side=tk.LEFT)
        self.kl_verdict = tk.Label(ctrl, text="Click to scan", font=("Consolas",9,"bold"),
                                    bg=T["BG_CARD"], fg=T["TEXT_DIM"]); self.kl_verdict.pack(side=tk.LEFT, padx=14)
        tf = tk.Frame(parent, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        cols = ("Type","Severity","Name / Path","Detail")
        self.kl_tree = ttk.Treeview(tf, columns=cols, show="headings")
        for col,w in zip(cols,[100,80,260,400]):
            self.kl_tree.heading(col,text=col); self.kl_tree.column(col,width=w,anchor="w")
        self.kl_tree.tag_configure("CRITICAL",foreground=T["RED"])
        self.kl_tree.tag_configure("HIGH",    foreground=T["ORANGE"])
        self.kl_tree.tag_configure("LOW",     foreground=T["GREEN"])
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.kl_tree.yview)
        self.kl_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.kl_tree.pack(fill=tk.BOTH,expand=True)

    def _kl_scan(self):
        self.kl_verdict.configure(text="Scanning...", fg=T["TEXT_DIM"])
        threading.Thread(target=lambda: self._ui( lambda: self._kl_show(scan_keylogger_indicators())), daemon=True).start()
    def _kl_show(self, r):
        for row in self.kl_tree.get_children(): self.kl_tree.delete(row)
        color = T["RED"] if r["risk"]=="CRITICAL" else T["ORANGE"] if r["risk"]=="HIGH" else T["GREEN"]
        self.kl_verdict.configure(text=r["verdict"], fg=color)
        for h in r.get("hits",[]):
            sev = h.get("severity","LOW")
            self.kl_tree.insert("","end",values=(h.get("type","?"),sev,
                h.get("name","?")[:50],h.get("detail","?")[:80]),tags=(sev,))
        if not r.get("hits"):
            self.kl_tree.insert("","end",values=("✓","LOW","System clean","No keylogger indicators"),tags=("LOW",))

    # ══════════════════════════════════════════════════════════════════════
    # TAB: PORT KNOCKING DETECTOR
    # ══════════════════════════════════════════════════════════════════════
    def _tab_port_knock(self, parent):
        tk.Label(parent, text="  ◈  PORT KNOCKING DETECTOR",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Suspicious port sequence attempts — attacker recon identify karo",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["CYAN"], height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔍 DETECT PORT KNOCKING", font=("Consolas",10,"bold"),
                  bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=16, pady=7, command=self._pk_scan).pack(side=tk.LEFT)
        self.pk_verdict = tk.Label(ctrl, text="", font=("Consolas",9), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.pk_verdict.pack(side=tk.LEFT, padx=12)
        self.pk_text = tk.Text(parent, font=("Consolas",9), bg=T["LOG_BG"], fg=T["TEXT_MID"],
                                relief=tk.FLAT, padx=12, pady=8, state=tk.DISABLED, wrap=tk.WORD)
        self.pk_text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.pk_text.tag_configure("hit",  foreground=T["ORANGE"], font=("Consolas",9,"bold"))
        self.pk_text.tag_configure("good", foreground=T["GREEN"])
        self.pk_text.tag_configure("head", foreground=T["CYAN"],   font=("Consolas",9,"bold"))

    def _pk_scan(self):
        self.pk_verdict.configure(text="Scanning...")
        threading.Thread(target=lambda: self._ui( lambda: self._pk_show(detect_port_knocking())), daemon=True).start()
    def _pk_show(self, r):
        color = T["ORANGE"] if r["risk"]=="HIGH" else T["GREEN"]
        self.pk_verdict.configure(text=r["verdict"], fg=color)
        self.pk_text.configure(state=tk.NORMAL); self.pk_text.delete(1.0,tk.END)
        self.pk_text.insert(tk.END, f"Scan Time: {r.get('checked_at','')}\n\n","head")
        if r.get("hits"):
            for h in r["hits"]:
                self.pk_text.insert(tk.END, f"⚠ {h['detail']}\n","hit")
                if h.get("ports"): self.pk_text.insert(tk.END, f"   Ports: {h['ports']}\n")
        else:
            self.pk_text.insert(tk.END, "✓ No port knocking sequences detected\n\n","good")
            self.pk_text.insert(tk.END,
                "Port knocking = attacker sends packets to closed ports in sequence\n"
                "to trigger hidden service. Firewall logs monitored for patterns.","head")
        self.pk_text.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: DISK ANALYZER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_disk(self, parent):
        tk.Label(parent, text="  ◈  DISK USAGE ANALYZER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["ORANGE"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Frame(parent, bg=T["ORANGE"], height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔄 REFRESH", font=("Consolas",10,"bold"), bg=T["ORANGE"],
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=14, pady=6,
                  command=self._disk_refresh).pack(side=tk.LEFT)
        self.disk_frame = tk.Frame(parent, bg=T["BG_DEEP"])
        self.disk_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.after(625, self._disk_refresh)

    def _disk_refresh(self):
        for w in self.disk_frame.winfo_children(): w.destroy()
        for d in get_disk_usage():
            card = tk.Frame(self.disk_frame, bg=T["BG_CARD"], padx=16, pady=10)
            card.pack(fill=tk.X, pady=4)
            pct   = d.get("pct",0)
            color = T["RED"] if pct>90 else T["ORANGE"] if pct>75 else T["GREEN"]
            hdr = tk.Frame(card, bg=T["BG_CARD"]); hdr.pack(fill=tk.X)
            tk.Label(hdr, text=f"💾 {d.get('path','?')}  ({d.get('fstype','')})",
                     font=("Consolas",10,"bold"), bg=T["BG_CARD"], fg=color).pack(side=tk.LEFT)
            tk.Label(hdr, text=f"{d.get('used_gb',0)} GB / {d.get('total_gb',0)} GB  ({pct}%)",
                     font=("Consolas",9), bg=T["BG_CARD"], fg=T["TEXT_MID"]).pack(side=tk.RIGHT)
            bar = tk.Frame(card, bg=T["BG_ELEVATED"], height=18); bar.pack(fill=tk.X, pady=4)
            bar.update_idletasks()
            bw = max(1, int(bar.winfo_width() * pct / 100))
            tk.Frame(bar, bg=color, height=18, width=bw).place(x=0,y=0)
            info = tk.Frame(card, bg=T["BG_CARD"]); info.pack(fill=tk.X)
            for lbl, clr in [(f"Free: {d.get('free_gb',0)}GB", T["GREEN"]),
                              (f"Used: {d.get('used_gb',0)}GB", color),
                              (f"Total: {d.get('total_gb',0)}GB", T["TEXT_DIM"])]:
                tk.Label(info, text=lbl, font=("Consolas",8), bg=T["BG_CARD"], fg=clr).pack(side=tk.LEFT, padx=8)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: TOP NETWORK CONNECTIONS
    # ══════════════════════════════════════════════════════════════════════
    def _tab_netconn(self, parent):
        tk.Label(parent, text="  ◈  TOP 15 NETWORK CONNECTIONS (LIVE)",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Frame(parent, bg=T["CYAN"], height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔄 REFRESH", font=("Consolas",10,"bold"), bg=T["CYAN"],
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=14, pady=6,
                  command=self._nc_refresh).pack(side=tk.LEFT)
        self.nc_auto_var = tk.BooleanVar(value=False)
        tk.Checkbutton(ctrl, text="AUTO (3s)", font=("Consolas",9),
                       variable=self.nc_auto_var, bg=T["BG_CARD"], fg=T["CYAN"],
                       selectcolor=T["BG_ELEVATED"], activebackground=T["BG_CARD"],
                       command=self._nc_toggle_auto).pack(side=tk.LEFT, padx=8)
        self.nc_status = tk.Label(ctrl, text="", font=("Consolas",8), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.nc_status.pack(side=tk.LEFT)
        tf = tk.Frame(parent, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        cols = ("Process","Local Address","Remote Address","Status","PID")
        self.nc_tree = ttk.Treeview(tf, columns=cols, show="headings")
        for col,w in zip(cols,[160,180,180,110,60]):
            self.nc_tree.heading(col,text=col); self.nc_tree.column(col,width=w,anchor="w")
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.nc_tree.yview)
        self.nc_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.nc_tree.pack(fill=tk.BOTH,expand=True)
        self.after(650, self._nc_refresh)

    def _nc_refresh(self):
        conns = get_top_connections()
        for r in self.nc_tree.get_children(): self.nc_tree.delete(r)
        for c in conns:
            self.nc_tree.insert("","end",values=(c.get("process","?")[:25],
                c.get("local","?"),c.get("remote","?"),c.get("status","?"),c.get("pid","")))
        self.nc_status.configure(text=f"{len(conns)} connections | {datetime.now().strftime('%H:%M:%S')}")
    def _nc_toggle_auto(self):
        if self.nc_auto_var.get(): self._nc_auto_tick()
    def _nc_auto_tick(self):
        if self.nc_auto_var.get(): self._nc_refresh(); self.after(3000, self._nc_auto_tick)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: LOGIN ATTEMPT LOGGER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_loginlog(self, parent):
        tk.Label(parent, text="  ◈  LOGIN ATTEMPT LOGGER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#FF44AA",
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Windows Event Log se login success/failure history",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg="#FF44AA", height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="📜 LOAD LOGIN HISTORY", font=("Consolas",10,"bold"),
                  bg="#FF44AA", fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=16, pady=7, command=self._login_load).pack(side=tk.LEFT)
        self.login_status = tk.Label(ctrl, text="", font=("Consolas",9), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.login_status.pack(side=tk.LEFT, padx=12)
        tf = tk.Frame(parent, bg=T["BG_DEEP"]); tf.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        cols = ("Time","Type","Account","Event ID")
        self.login_tree = ttk.Treeview(tf, columns=cols, show="headings")
        for col,w in zip(cols,[170,90,200,80]):
            self.login_tree.heading(col,text=col); self.login_tree.column(col,width=w,anchor="w")
        self.login_tree.tag_configure("FAILURE",foreground=T["RED"])
        self.login_tree.tag_configure("SUCCESS",foreground=T["GREEN"])
        self.login_tree.tag_configure("INFO",   foreground=T["CYAN"])
        vsb=ttk.Scrollbar(tf,orient=tk.VERTICAL,command=self.login_tree.yview)
        self.login_tree.configure(yscrollcommand=vsb.set); vsb.pack(side=tk.RIGHT,fill=tk.Y)
        self.login_tree.pack(fill=tk.BOTH,expand=True)
        tk.Label(parent, text="ℹ  Run as Administrator for full Security Event Log access",
                 font=("Segoe UI",8), bg=T["BG_ELEVATED"], fg=T["TEXT_DIM"],
                 anchor="w", padx=12, pady=5).pack(fill=tk.X)

    def _login_load(self):
        self.login_status.configure(text="Loading...")
        threading.Thread(target=lambda: self._ui( lambda: self._login_show(get_login_attempts())), daemon=True).start()
    def _login_show(self, attempts):
        for r in self.login_tree.get_children(): self.login_tree.delete(r)
        fails = sum(1 for a in attempts if a.get("type")=="FAILURE")
        for a in attempts:
            t = a.get("type","INFO")
            self.login_tree.insert("","end",values=(a.get("time","?"),t,
                a.get("account","?"),a.get("event_id","")),tags=(t,))
        self.login_status.configure(text=f"{len(attempts)} events | Failures: {fails}"
            + (" ⚠ Brute force?" if fails>5 else ""))

    # ══════════════════════════════════════════════════════════════════════
    # TAB: BATTERY & UPTIME
    # ══════════════════════════════════════════════════════════════════════
    def _tab_battery(self, parent):
        tk.Label(parent, text="  ◈  BATTERY & SYSTEM UPTIME MONITOR",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["GREEN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Frame(parent, bg=T["GREEN"], height=2).pack(fill=tk.X)
        content = tk.Frame(parent, bg=T["BG_DEEP"]); content.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
        bat_card = tk.Frame(content, bg=T["BG_CARD"], padx=20, pady=16); bat_card.pack(fill=tk.X)
        tk.Frame(bat_card, bg=T["GREEN"], height=2).pack(fill=tk.X, pady=(0,10))
        tk.Label(bat_card, text="🔋 BATTERY STATUS", font=("Consolas",10,"bold"),
                 bg=T["BG_CARD"], fg=T["GREEN"], anchor="w").pack(fill=tk.X)
        bat_row = tk.Frame(bat_card, bg=T["BG_CARD"]); bat_row.pack(fill=tk.X, pady=8)
        self.bat_pct_lbl    = tk.Label(bat_row, text="--", font=("Consolas",40,"bold"), bg=T["BG_CARD"], fg=T["GREEN"])
        self.bat_pct_lbl.pack(side=tk.LEFT)
        tk.Label(bat_row, text="%", font=("Consolas",18), bg=T["BG_CARD"], fg=T["GREEN"]).pack(side=tk.LEFT)
        bat_info = tk.Frame(bat_row, bg=T["BG_CARD"]); bat_info.pack(side=tk.LEFT, padx=20)
        self.bat_status_lbl = tk.Label(bat_info, text="", font=("Consolas",11,"bold"), bg=T["BG_CARD"], fg=T["CYAN"])
        self.bat_status_lbl.pack(anchor="w")
        self.bat_time_lbl   = tk.Label(bat_info, text="", font=("Consolas",10), bg=T["BG_CARD"], fg=T["TEXT_MID"])
        self.bat_time_lbl.pack(anchor="w")
        self.bat_bar = tk.Frame(bat_card, bg=T["BG_ELEVATED"], height=18); self.bat_bar.pack(fill=tk.X, pady=6)
        up_card = tk.Frame(content, bg=T["BG_CARD"], padx=20, pady=16); up_card.pack(fill=tk.X, pady=(12,0))
        tk.Frame(up_card, bg=T["CYAN"], height=2).pack(fill=tk.X, pady=(0,10))
        tk.Label(up_card, text="⏱ SYSTEM UPTIME", font=("Consolas",10,"bold"),
                 bg=T["BG_CARD"], fg=T["CYAN"], anchor="w").pack(fill=tk.X)
        self.uptime_lbl = tk.Label(up_card, text="--", font=("Consolas",32,"bold"), bg=T["BG_CARD"], fg=T["CYAN"])
        self.uptime_lbl.pack(anchor="w", pady=4)
        self.boot_lbl   = tk.Label(up_card, text="", font=("Consolas",9), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.boot_lbl.pack(anchor="w")
        tk.Button(content, text="🔄 REFRESH", font=("Consolas",10,"bold"),
                  bg=T["GREEN_DIM"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=7, command=self._bat_refresh).pack(anchor="w", pady=10)
        self.after(675, self._bat_refresh)
    def _tab_uptime(self, parent):
        self._tab_battery(parent)
    def _bat_refresh(self):
        bat = get_battery_info(); up = get_uptime()
        if bat.get("available"):
            pct   = bat["percent"]
            color = T["RED"] if pct<20 else T["ORANGE"] if pct<50 else T["GREEN"]
            self.bat_pct_lbl.configure(text=str(int(pct)), fg=color)
            self.bat_status_lbl.configure(text=bat.get("status",""))
            self.bat_time_lbl.configure(text=bat.get("time_left",""))
            self.bat_bar.update_idletasks()
            for w in self.bat_bar.winfo_children(): w.destroy()
            bw = max(1, int(self.bat_bar.winfo_width() * pct / 100))
            tk.Frame(self.bat_bar, bg=color, height=18, width=bw).place(x=0,y=0)
        else:
            self.bat_pct_lbl.configure(text="N/A", fg=T["TEXT_DIM"])
            self.bat_status_lbl.configure(text="Desktop / No battery")
        self.uptime_lbl.configure(text=up.get("uptime_str","--"))
        self.boot_lbl.configure(text=f"Last boot: {up.get('boot_time','--')}")

    # ══════════════════════════════════════════════════════════════════════
    # TAB: HASH TOOLS + BASE64 + SUBNET CALC
    # ══════════════════════════════════════════════════════════════════════
    def _tab_hashtools(self, parent):
        tk.Label(parent, text="  ◈  SECURITY TOOLS — HASH / BASE64 / SUBNET CALC",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#AA44FF",
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Frame(parent, bg="#AA44FF", height=2).pack(fill=tk.X)
        nb2 = ttk.Notebook(parent); nb2.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        # ── Hash ──
        hf = tk.Frame(nb2, bg=T["BG_DEEP"]); nb2.add(hf, text="  🔑 Hash Calc  ")
        tk.Label(hf, text="Input text:", font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"], fg=T["CYAN"], anchor="w", padx=10, pady=6).pack(fill=tk.X)
        self.hash_input = tk.Text(hf, font=("Consolas",10), height=4, bg=T["BG_CARD"],
                                   fg=T["GREEN"], insertbackground=T["GREEN"], relief=tk.FLAT, padx=10, pady=6)
        self.hash_input.pack(fill=tk.X, padx=8)
        hr = tk.Frame(hf, bg=T["BG_DEEP"], pady=4); hr.pack(fill=tk.X, padx=8)
        tk.Button(hr, text="# CALCULATE", font=("Consolas",10,"bold"), bg="#AA44FF",
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=12, pady=5,
                  command=self._calc_hash).pack(side=tk.LEFT)
        tk.Button(hr, text="📂 FROM FILE", font=("Consolas",9), bg=T["BG_ELEVATED"],
                  fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=8, pady=5,
                  command=self._hash_from_file).pack(side=tk.LEFT, padx=6)
        self.hash_results = {}
        for algo in ["md5","sha1","sha256","sha512"]:
            row = tk.Frame(hf, bg=T["BG_CARD"], padx=10, pady=6); row.pack(fill=tk.X, padx=8, pady=2)
            tk.Label(row, text=algo.upper()+":", font=("Consolas",8,"bold"),
                     bg=T["BG_CARD"], fg="#AA44FF", width=8, anchor="w").pack(side=tk.LEFT)
            var = tk.StringVar(value="--")
            tk.Label(row, textvariable=var, font=("Consolas",9), bg=T["BG_CARD"],
                     fg=T["GREEN"], anchor="w").pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Button(row, text="📋", font=("Consolas",9), bg=T["BG_ELEVATED"], fg=T["TEXT_DIM"],
                      relief=tk.FLAT, cursor="hand2",
                      command=lambda v=var:(self.clipboard_clear(),self.clipboard_append(v.get()))
                      ).pack(side=tk.RIGHT)
            self.hash_results[algo] = var
        # ── Base64 ──
        bf = tk.Frame(nb2, bg=T["BG_DEEP"]); nb2.add(bf, text="  📦 Base64  ")
        tk.Label(bf, text="Input:", font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"], fg=T["CYAN"], anchor="w", padx=10, pady=6).pack(fill=tk.X)
        self.b64_input = tk.Text(bf, font=("Consolas",10), height=5, bg=T["BG_CARD"],
                                  fg=T["GREEN"], insertbackground=T["GREEN"], relief=tk.FLAT, padx=10, pady=6)
        self.b64_input.pack(fill=tk.X, padx=8)
        b64r = tk.Frame(bf, bg=T["BG_DEEP"], pady=6); b64r.pack(fill=tk.X, padx=8)
        tk.Button(b64r, text="🔒 ENCODE", font=("Consolas",10,"bold"), bg=T["CYAN"],
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=12, pady=5,
                  command=lambda:self._b64_op("encode")).pack(side=tk.LEFT)
        tk.Button(b64r, text="🔓 DECODE", font=("Consolas",10,"bold"), bg=T["GREEN_DIM"],
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=12, pady=5,
                  command=lambda:self._b64_op("decode")).pack(side=tk.LEFT, padx=6)
        tk.Label(bf, text="Output:", font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"], fg=T["ORANGE"], anchor="w", padx=10).pack(fill=tk.X)
        self.b64_output = tk.Text(bf, font=("Consolas",10), height=5, bg=T["LOG_BG"],
                                   fg=T["ORANGE"], relief=tk.FLAT, padx=10, pady=6, state=tk.DISABLED)
        self.b64_output.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        # ── Subnet Calc ──
        sf = tk.Frame(nb2, bg=T["BG_DEEP"]); nb2.add(sf, text="  🌐 Subnet Calc  ")
        tk.Label(sf, text="IP / CIDR (e.g. 192.168.1.0/24):", font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"], fg=T["CYAN"], anchor="w", padx=10, pady=10).pack(fill=tk.X)
        self.subnet_input = tk.StringVar(value="192.168.1.0/24")
        sfe = tk.Frame(sf, bg=T["CYAN"], padx=1, pady=1); sfe.pack(fill=tk.X, padx=8)
        se = tk.Entry(sfe, textvariable=self.subnet_input, font=("Consolas",13),
                      bg=T["BG_CARD"], fg=T["CYAN"], insertbackground=T["CYAN"],
                      relief=tk.FLAT, bd=6); se.pack(fill=tk.X)
        se.bind("<Return>", lambda e:self._subnet_calc())
        tk.Button(sf, text="⚡ CALCULATE", font=("Consolas",10,"bold"), bg=T["CYAN"],
                  fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2", padx=14, pady=7,
                  command=self._subnet_calc).pack(anchor="w", padx=8, pady=8)
        self.subnet_rf = tk.Frame(sf, bg=T["BG_DEEP"]); self.subnet_rf.pack(fill=tk.BOTH, expand=True, padx=8)
        self._subnet_calc()

    def _calc_hash(self):
        r = calculate_hashes(text=self.hash_input.get(1.0,tk.END).strip())
        for algo,var in self.hash_results.items(): var.set(r.get(algo,"--"))
    def _hash_from_file(self):
        path = filedialog.askopenfilename()
        if path:
            r = calculate_hashes(filepath=path)
            for algo,var in self.hash_results.items(): var.set(r.get(algo,"--"))
    def _b64_op(self, op):
        text   = self.b64_input.get(1.0,tk.END).strip()
        result = b64_encode(text) if op=="encode" else b64_decode(text)
        self.b64_output.configure(state=tk.NORMAL); self.b64_output.delete(1.0,tk.END)
        self.b64_output.insert(tk.END,result); self.b64_output.configure(state=tk.DISABLED)
    def _subnet_calc(self):
        for w in self.subnet_rf.winfo_children(): w.destroy()
        r = subnet_calc(self.subnet_input.get().strip())
        if "error" in r:
            tk.Label(self.subnet_rf,text=f"Error: {r['error']}",font=("Consolas",10),
                     bg=T["BG_DEEP"],fg=T["RED"]).pack(); return
        for label,value,color in [
            ("Network",       r.get("network","?"),                              T["CYAN"]),
            ("Subnet Mask",   r.get("subnet_mask","?"),                          T["TEXT_MID"]),
            ("Broadcast",     r.get("broadcast","?"),                            T["ORANGE"]),
            ("First Host",    r.get("first_host","?"),                           T["GREEN"]),
            ("Last Host",     r.get("last_host","?"),                            T["GREEN"]),
            ("Usable Hosts",  f"{r.get('usable_hosts',0):,}",                   T["YELLOW"]),
            ("Total IPs",     f"{r.get('total_hosts',0):,}",                    T["TEXT_MID"]),
            ("IP Class",      r.get("ip_class","?"),                             T["CYAN"]),
            ("Private",       "YES ✓" if r.get("is_private") else "NO (Public)",
                              T["GREEN"] if r.get("is_private") else T["ORANGE"]),
        ]:
            row = tk.Frame(self.subnet_rf,bg=T["BG_CARD"]); row.pack(fill=tk.X,pady=2,padx=4)
            tk.Label(row,text=f"{label}:",font=("Consolas",9),bg=T["BG_CARD"],
                     fg=T["TEXT_DIM"],width=14,anchor="w").pack(side=tk.LEFT)
            tk.Label(row,text=value,font=("Consolas",10,"bold"),bg=T["BG_CARD"],fg=color).pack(side=tk.LEFT,padx=8)

        # SCAN LOGIC
    # ══════════════════════════════════════════════════════════════════════

    def _redetect_ip(self):
        ip=detect_local_ip(); self.ip_var.set(ip)
        self._log(f"[AUTO-DETECT] {ip}","green"); self._set_status(f"IP: {ip}")

    def _on_scan(self):
        if self.scan_running: messagebox.showwarning("Busy","Scan running!"); return
        target=self.ip_var.get().strip()
        if not target: messagebox.showerror("Error","Enter IP."); return
        self._clear()
        self.scan_running=True
        try: self.btn_scan.configure(state=tk.DISABLED,
                                       text=self.L.get("btn_scanning","◉ SCANNING..."),
                                       bg=T["CYAN_DIM"])
        except Exception: pass
        try: self.btn_report.configure(state=tk.DISABLED)
        except Exception: pass
        try: self.btn_email.configure(state=tk.DISABLED)
        except Exception: pass
        None  # progress bar removed; self.scan_idle_lbl.configure(text="● SCANNING",fg=T["CYAN"])
        self._set_status(f"SCANNING: {target}")
        self._log("╔══════════════════════════════════════╗","cyan")
        self._log("║  AI VULNERABILITY ASSESSMENT SCAN    ║","cyan")
        self._log("╚══════════════════════════════════════╝","cyan")
        self._log(f"  TARGET: {target}","bright")
        self._log(f"  TIME:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}","dim")
        threading.Thread(target=self._scan_bg,args=(target,),daemon=True).start()

    def _scan_bg(self,target):
        try:
            sc=VulnerabilityScanner(target)
            self.scan_results=sc.run_full_scan(
                progress_callback=lambda m:self._log_safe(m,self._gtag(m)))
            self._log_safe("  [AI] Analysing risks...","cyan")
            eng=RiskAssessmentEngine(self.scan_results)
            self.risk_result=eng.analyse()
            self._show_results()
            self.scan_history.add_entry(self.scan_results,self.risk_result)
            self._ui(self._load_history)
        except Exception as e:
            self._log_safe(f"  [ERROR] {e}","red")
        finally:
            self._ui(self._scan_done)

    def _scan_done(self):
        self.scan_running = False
        try: self.btn_scan.configure(state=tk.NORMAL,
                                      text=self.L.get("btn_scan","▶ SCAN"),
                                      bg=T["CYAN"])
        except Exception: pass
        try: self.scan_idle_lbl.configure(text="● COMPLETE", fg=T["GREEN"])
        except Exception: pass
        if self.risk_result:
            try: self.btn_report.configure(state=tk.NORMAL)
            except Exception: pass
            try: self.btn_email.configure(state=tk.NORMAL)
            except Exception: pass
            lv=self.risk_result.get("risk_level","LOW"); sc=self.risk_result.get("risk_score",0)
            self._set_status(f"{self.L['scan_complete']}  ●  {lv}  ●  {sc}/100")
            # Auto-save to score graph
            try: add_scan_point(sc, lv, self.ip_var.get())
            except Exception: pass
            # Update scan status pill and security indicators
            try:
                pill_color = {"CRITICAL":T["RED"],"HIGH":T["ORANGE"],"MEDIUM":T["YELLOW"],"LOW":T["GREEN"]}.get(lv,T["CYAN"])
                self.scan_status_pill.configure(text=f"● {lv}  {sc}/100", fg=pill_color, bg=T["BG_CARD"])
                self.scan_idle_lbl.configure(text=f"● {lv}", fg=pill_color)
            except Exception: pass
            # Update security indicators
            try:
                scan = self.scan_results or {}
                fw_ok = scan.get("firewall_enabled", False)
                av_ok = scan.get("antivirus_active", False)
                up_ok = scan.get("os_updates", "UNKNOWN") == "UP-TO-DATE"
                self.sec_ind["firewall"].configure(
                    text="ENABLED" if fw_ok else "DISABLED",
                    fg=T["GREEN"] if fw_ok else T["RED"])
                self.sec_ind["antivirus"].configure(
                    text="ACTIVE" if av_ok else "INACTIVE",
                    fg=T["GREEN"] if av_ok else T["RED"])
                self.sec_ind["updates"].configure(
                    text="UP TO DATE" if up_ok else "PENDING",
                    fg=T["GREEN"] if up_ok else T["ORANGE"])
            except Exception: pass
            # AI Agent auto-analysis
            try:
                ai_msg = ""
                if lv == "CRITICAL":
                    ai_msg = "🚨 CRITICAL risk! Immediate action needed. Open ports are high risk. Check Firewall tab."
                elif lv == "HIGH":
                    ai_msg = "⚠ HIGH risk detected. Review open ports. Run Auto-Fix for quick remediation."
                elif lv == "MEDIUM":
                    ai_msg = "⚡ MEDIUM risk. Some vulnerabilities found. Check Auto-Fix tab for patches."
                else:
                    ai_msg = "✅ LOW risk. System looks good! Continue monitoring regularly."
                ports = len((self.scan_results or {}).get("open_ports",[]))
                if ports > 0:
                    ai_msg += f" ({ports} open port{'s' if ports!=1 else ''} detected)"
                self.ai_agent_lbl.configure(text=ai_msg,
                    fg={"CRITICAL":T["RED"],"HIGH":T["ORANGE"],"MEDIUM":T["YELLOW"],"LOW":T["GREEN"]}.get(lv,T["CYAN"]))
            except Exception: pass

    def _show_results(self):
        if not self.risk_result: return
        score=self.risk_result["risk_score"]; level=self.risk_result["risk_level"]
        sub=self.risk_result["sub_scores"]; recs=self.risk_result["recommendations"]
        thrs=self.risk_result["threats"]
        tag={"CRITICAL":"critical","HIGH":"orange","MEDIUM":"yellow","LOW":"green"}.get(level,"cyan")
        self._log_safe("","dim")
        self._log_safe("╔══════════════════════════════════════╗","cyan")
        self._log_safe("║  AI RISK ASSESSMENT RESULTS          ║","cyan")
        self._log_safe("╚══════════════════════════════════════╝","cyan")
        self._log_safe(f"  SCORE: {score}/100  |  LEVEL: {level}",tag)
        for k,l,w in [("open_ports","Open Ports","25%"),("firewall","Firewall","25%"),
                       ("os_updates","OS Updates","20%"),("antivirus","Antivirus","20%"),
                       ("critical_ports","Crit Ports","10%")]:
            v=sub.get(k,0); bar="█"*int(v/5)+"░"*(20-int(v/5))
            t2="red" if v>=70 else "orange" if v>=50 else "yellow" if v>=30 else "green"
            self._log_safe(f"  {l:<14}[{bar}]{v:>3}/100 ({w})",t2)
        self._log_safe("","dim")
        for t in thrs:
            self._log_safe(f"  {t}","red" if "⚠" in t or "🔴" in t else "green")
        self._log_safe("","dim")
        for r in recs:
            tg={"CRITICAL":"red","HIGH":"orange","MEDIUM":"yellow","LOW":"green"}.get(r["priority"],"dim")
            self._log_safe(f"  [{r['priority']:<8}] {r['action']}",tg)
        self._log_safe("  ► PDF + Email buttons active","cyan")
        self._ui(lambda:self._update_visuals(score,level,sub))

    def _update_visuals(self,score,level,sub):
        self.risk_meter.animate_to(score,level)
        for key,bar in self.f_bars.items():
            v=sub.get(key,0)
            c=T["RED"] if v>=70 else T["ORANGE"] if v>=50 else T["YELLOW"] if v>=30 else T["GREEN"]
            bar.animate_to(v,c); self.f_lbls[key].configure(text=f"{v:.0f}%",fg=c)
        scan=self.scan_results or {}
        fw=scan.get("firewall_status","Unknown").upper()
        av=scan.get("antivirus_status","Unknown").upper()
        upd=scan.get("os_update_status","Unknown").upper()
        self.sec_ind["firewall"].configure(
            text="ON" if fw=="ENABLED" else "OFF" if fw=="DISABLED" else "?",
            fg=T["GREEN"] if fw=="ENABLED" else T["RED"] if fw=="DISABLED" else T["YELLOW"])
        self.sec_ind["antivirus"].configure(
            text="ACTIVE" if av=="ACTIVE" else "OFF" if av=="INACTIVE" else "?",
            fg=T["GREEN"] if av=="ACTIVE" else T["RED"] if av=="INACTIVE" else T["YELLOW"])
        ut="OK" if "UP-TO-DATE" in upd or "UP_TO_DATE" in upd else "NEEDED" if "AVAIL" in upd else "?"
        self.sec_ind["updates"].configure(text=ut,
            fg=T["GREEN"] if ut=="OK" else T["RED"] if ut=="NEEDED" else T["YELLOW"])

    def _on_report(self):
        if not self.scan_results or not self.risk_result:
            messagebox.showwarning("No Data","Run a scan first."); return
        path=filedialog.asksaveasfilename(defaultextension=".pdf",
            filetypes=[("PDF","*.pdf")],
            initialfile=f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        if not path: return
        try:
            gen=ReportGenerator(self.scan_results,self.risk_result)
            res=gen.generate_pdf(path)
            if res.startswith("ERROR"): messagebox.showerror("Error",res)
            else:
                self._log(f"[PDF] Saved: {res}","green")
                messagebox.showinfo("Exported",f"PDF saved:\n{res}")
                if messagebox.askyesno("Open?","Open now?"): os.startfile(res)
        except Exception as e:
            messagebox.showerror("Error",str(e))

    def _on_email(self):
        messagebox.showinfo("Email Report",
            "To send email:\n\n"
            "1. First export PDF using 'EXPORT PDF'\n"
            "2. Use email_report.py module directly\n\n"
            "Gmail setup:\n"
            "myaccount.google.com → Security → App Passwords\n"
            "Generate 16-char app password\n\n"
            "Run: python -c \"from email_report import send_report_email; ...\"")

    # ── STATUS BAR ────────────────────────────────────────────────────────

    def _build_statusbar(self):
        bar=tk.Frame(self,bg=T["BG_PANEL"]); bar.pack(fill=tk.X,side=tk.BOTTOM)
        tk.Frame(bar,bg=T["CYAN_DIM"],height=1).pack(fill=tk.X)
        inner=tk.Frame(bar,bg=T["BG_PANEL"]); inner.pack(fill=tk.X,padx=12,pady=4)
        self.status_var=tk.StringVar(value="SYSTEM READY")
        tk.Label(inner,textvariable=self.status_var,font=("Consolas",8),
                 bg=T["BG_PANEL"],fg=T["CYAN_DIM"],anchor="w").pack(side=tk.LEFT)
        tk.Label(inner,text="CYBERSHIELD PRO v11.0  ●  SecureNet Solutions  ●  FYP 2026",
                 font=("Consolas",8),bg=T["BG_PANEL"],fg=T["TEXT_DIM"],anchor="e").pack(side=tk.RIGHT)

    # ── HELPERS ───────────────────────────────────────────────────────────

    def _log(self,msg,tag="dim"):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.insert(tk.END,msg+"\n",tag)
        self.log_area.see(tk.END)
        self.log_area.configure(state=tk.DISABLED)

    def _log_safe(self,msg,tag="dim"):
        try:
            self._ui( lambda m=msg, t=tag: self._log(m, t))
        except RuntimeError: pass

    def _gtag(self,m):
        ml=m.lower()
        if "error" in ml or "[!]" in ml: return "red"
        if "open" in ml and "port" in ml: return "orange"
        if "✓" in m or "enabled" in ml or "active" in ml: return "green"
        if "[*]" in m: return "cyan"
        return "dim"

    def _clear(self):
        self.log_area.configure(state=tk.NORMAL)
        self.log_area.delete(1.0,tk.END)
        self.log_area.configure(state=tk.DISABLED)
        self.risk_meter.reset()
        for bar in self.f_bars.values(): bar.set_value(0)
        for lbl in self.f_lbls.values(): lbl.configure(text="--",fg=T["TEXT_DIM"])
        for lbl in self.sec_ind.values(): lbl.configure(text="...",fg=T["TEXT_DIM"])
        self.scan_results=None; self.risk_result=None
        self.btn_report.configure(state=tk.DISABLED)
        self.btn_email.configure(state=tk.DISABLED)
        self._log("[SYSTEM] Ready.","cyan")

    def _set_status(self,msg): self.status_var.set(msg)


    # ══════════════════════════════════════════════════════════════════════
    # SIDEBAR + TRAY + THREAT SCORE HELPERS
    # ══════════════════════════════════════════════════════════════════════
    def _build_sidebar(self, parent):
        SIDEBAR_ITEMS = [
            ("🏠","DASH",     0),
            ("🔍","SCAN",     0),
            ("📊","MONITOR",  2),
            ("🔑","WiFi PW",  30),
            ("🤖","AI CHAT",  -2),
            ("🎲","PW GEN",   -3),
            ("🛡","SECURITY", 12),
            ("⚠","CVE",       28),
        ]
        sb = tk.Frame(parent, bg="#010D1A", width=64)
        sb.pack(side=tk.LEFT, fill=tk.Y); sb.pack_propagate(False)
        tk.Frame(sb, bg=T["CYAN"], width=2).pack(side=tk.RIGHT, fill=tk.Y)
        self._sb_btns = {}
        for icon, label, idx in SIDEBAR_ITEMS:
            bf = tk.Frame(sb, bg="#010D1A"); bf.pack(fill=tk.X, pady=3, padx=3)
            btn = tk.Button(bf, text=icon, font=("Segoe UI Emoji",17),
                           bg="#010D1A", fg=T["TEXT_DIM"], relief=tk.FLAT,
                           width=3, cursor="hand2")
            btn.pack(); 
            lbl = tk.Label(bf, text=label, font=("Consolas",5,"bold"),
                          bg="#010D1A", fg=T["TEXT_DIM"])
            lbl.pack()
            def _make(i=idx, b=btn, l=lbl):
                def _go():
                    for b2,l2 in self._sb_btns.values():
                        b2.configure(bg="#010D1A", fg=T["TEXT_DIM"])
                        l2.configure(fg=T["TEXT_DIM"])
                    b.configure(bg=T["BG_ELEVATED"], fg=T["CYAN"])
                    l.configure(fg=T["CYAN"])
                    if i == -2:  # AI Chat
                        for n in range(self.nb.index("end")):
                            if "AI" in self.nb.tab(n,"text"):
                                self.nb.select(n); break
                    elif i == -3:  # PW Gen
                        for n in range(self.nb.index("end")):
                            if "PW GEN" in self.nb.tab(n,"text") or "GENERATOR" in self.nb.tab(n,"text"):
                                self.nb.select(n); break
                    elif i >= 0:
                        try: self.nb.select(i)
                        except Exception: pass
                return _go
            btn.configure(command=_make())
            btn.bind("<Enter>", lambda e,b=btn,l=lbl: (b.configure(bg=T["BG_CARD"]), l.configure(fg=T["CYAN"])) if b.cget("bg")!=T["BG_ELEVATED"] else None)
            btn.bind("<Leave>", lambda e,b=btn,l=lbl: (b.configure(bg="#010D1A"), l.configure(fg=T["TEXT_DIM"])) if b.cget("bg")!=T["BG_ELEVATED"] else None)
            self._sb_btns[label] = (btn, lbl)
        tk.Frame(sb, bg=T["BG_ELEVATED"], height=1).pack(fill=tk.X, pady=6)
        for icon, cmd in [("🌙", self._toggle_theme)]:
            tk.Button(sb, text=icon, font=("Segoe UI Emoji",15), bg="#010D1A",
                     fg=T["TEXT_DIM"], relief=tk.FLAT, width=3,
                     cursor="hand2", command=cmd).pack(pady=2)

    def _minimize_to_tray(self):
        try:
            import pystray
            from PIL import Image as PILImage, ImageDraw
            img  = PILImage.new("RGBA",(64,64),(0,0,0,0))
            draw = ImageDraw.Draw(img)
            draw.ellipse([4,4,60,60], fill=(0,212,255,255))
            draw.polygon([(32,12),(52,50),(12,50)], fill=(2,6,9,255))
            def _show(icon,item):
                icon.stop(); self._ui( self._restore_from_tray)
            def _quit(icon,item):
                icon.stop(); self._ui( self.destroy)
            import pystray as pst
            menu = pst.Menu(pst.MenuItem("🛡 Show",_show,default=True),
                           pst.MenuItem("❌ Quit",_quit))
            self._tray_icon = pst.Icon("FYP",img,"AI Security v10.0",menu)
            self.overrideredirect(False); self.withdraw()
            import threading
            threading.Thread(target=self._tray_icon.run, daemon=True).start()
        except ImportError:
            self.overrideredirect(False); self.iconify()
            self.bind("<Map>", lambda e: (self.deiconify(), self.overrideredirect(True)))
            self._set_status("pip install pystray pillow  — for full tray support")
        except Exception as ex:
            self._set_status(f"Tray error: {ex}")

    def _restore_from_tray(self):
        self.deiconify(); self.overrideredirect(True)
        self.lift(); self.focus_force()

    # ══════════════════════════════════════════════════════════════════════
    # TAB: AI SECURITY CHAT ASSISTANT
    # ══════════════════════════════════════════════════════════════════════
    def _tab_ai_chat(self, parent):
        hdr = tk.Frame(parent, bg="#0A0A1A"); hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg="#AA44FF", height=3).pack(fill=tk.X)
        row = tk.Frame(hdr, bg="#0A0A1A", padx=16, pady=10); row.pack(fill=tk.X)
        tk.Label(row, text="🤖", font=("Segoe UI Emoji",20),
                 bg="#0A0A1A", fg="#AA44FF").pack(side=tk.LEFT)
        info = tk.Frame(row, bg="#0A0A1A"); info.pack(side=tk.LEFT, padx=10)
        tk.Label(info, text="AI SECURITY ASSISTANT",
                 font=("Consolas",12,"bold"), bg="#0A0A1A", fg="#AA44FF").pack(anchor="w")
        tk.Label(info, text="VPN · Phishing · Ransomware · WiFi Security · Passwords aur bahut kuch",
                 font=("Segoe UI",8), bg="#0A0A1A", fg=T["TEXT_DIM"]).pack(anchor="w")
        tk.Label(row, text="● ONLINE", font=("Consolas",8,"bold"),
                 bg="#0A0A1A", fg=T["GREEN"]).pack(side=tk.RIGHT, padx=16)
        # Quick chips
        chips = tk.Frame(parent, bg=T["BG_DEEP"], padx=10, pady=6); chips.pack(fill=tk.X)
        tk.Label(chips, text="Quick:", font=("Consolas",8),
                 bg=T["BG_DEEP"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(0,6))
        for chip in ["What is VPN?","Explain ransomware","Strong password?","What is phishing?","WiFi security?","What is 2FA?"]:
            tk.Button(chips, text=chip, font=("Segoe UI",8), bg=T["BG_CARD"],
                     fg="#AA44FF", relief=tk.FLAT, cursor="hand2", padx=8, pady=3,
                     command=lambda q=chip: self._ai_send(q)).pack(side=tk.LEFT, padx=3)
        # Chat display
        cf = tk.Frame(parent, bg=T["BG_DEEP"]); cf.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.ai_chat_text = tk.Text(cf, font=("Consolas",10), bg="#070710",
                                     fg=T["TEXT_MID"], relief=tk.FLAT, padx=16, pady=12,
                                     state=tk.DISABLED, wrap=tk.WORD, cursor="arrow")
        vsb = ttk.Scrollbar(cf, orient=tk.VERTICAL, command=self.ai_chat_text.yview)
        self.ai_chat_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side=tk.RIGHT, fill=tk.Y); self.ai_chat_text.pack(fill=tk.BOTH, expand=True)
        self.ai_chat_text.tag_configure("user_bubble", foreground=T["CYAN"],   font=("Consolas",10,"bold"))
        self.ai_chat_text.tag_configure("ai_name",     foreground="#AA44FF",   font=("Consolas",10,"bold"))
        self.ai_chat_text.tag_configure("ai_text",     foreground=T["TEXT_MID"],font=("Consolas",9))
        self.ai_chat_text.tag_configure("ai_title",    foreground="#AA44FF",   font=("Consolas",10,"bold"))
        self.ai_chat_text.tag_configure("divider",     foreground=T["BG_ELEVATED"])
        # Input area
        ia = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=10); ia.pack(fill=tk.X)
        ib = tk.Frame(ia, bg="#AA44FF", padx=1, pady=1); ib.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ai_input = tk.Entry(ib, font=("Consolas",11), bg=T["BG_DEEP"],
                                  fg=T["TEXT_MID"], insertbackground="#AA44FF",
                                  relief=tk.FLAT, bd=8)
        self.ai_input.pack(fill=tk.X)
        self.ai_input.bind("<Return>", lambda e: self._ai_send())
        self.ai_input.insert(0, "Security sawaal poochhein... (e.g. 'What is VPN?')")
        self.ai_input.bind("<FocusIn>", lambda e: self.ai_input.delete(0,tk.END)
                          if "sawaal" in self.ai_input.get() else None)
        tk.Button(ia, text="➤ SEND", font=("Consolas",10,"bold"),
                  bg="#AA44FF", fg="white", relief=tk.FLAT, cursor="hand2",
                  padx=16, pady=8, command=self._ai_send).pack(side=tk.LEFT, padx=(8,0))
        tk.Button(ia, text="🗑 CLEAR", font=("Consolas",9), bg=T["BG_ELEVATED"],
                  fg=T["TEXT_DIM"], relief=tk.FLAT, cursor="hand2", padx=8, pady=8,
                  command=self._ai_clear).pack(side=tk.LEFT, padx=4)
        self.after(300, lambda: self._ai_show_response(get_ai_response("hello"), is_greeting=True))

    def _ai_send(self, text=None):
        query = text or self.ai_input.get().strip()
        if not query or "sawaal" in query: return
        self.ai_input.delete(0, tk.END)
        ts = datetime.now().strftime("%H:%M")
        self.ai_chat_text.configure(state=tk.NORMAL)
        self.ai_chat_text.insert(tk.END, "\n" + chr(128100) + " You [" + ts + "]\n", "user_bubble")
        self.ai_chat_text.insert(tk.END, "   " + query + "\n", "ai_text")
        self.ai_chat_text.configure(state=tk.DISABLED)
        self.ai_chat_text.see(tk.END)
        threading.Thread(target=lambda: self._ui( lambda: self._ai_show_response(
            get_ai_response(query))), daemon=True).start()

    def _ai_show_response(self, resp, is_greeting=False):
        ts = datetime.now().strftime("%H:%M")
        self.ai_chat_text.configure(state=tk.NORMAL)
        self.ai_chat_text.insert(tk.END, "\n" + chr(129302) + " AI Assistant [" + ts + "]\n", "ai_name")
        title = resp.get("title","")
        if title and not is_greeting:
            self.ai_chat_text.insert(tk.END, "   === " + title + " ===\n", "ai_title")
        for line in resp.get("answer","").split("\n"):
            self.ai_chat_text.insert(tk.END, "   " + line + "\n", "ai_text")
        self.ai_chat_text.insert(tk.END, "   " + chr(9472)*55 + "\n", "divider")
        self.ai_chat_text.configure(state=tk.DISABLED)
        self.ai_chat_text.see(tk.END)

    def _ai_clear(self):
        self.ai_chat_text.configure(state=tk.NORMAL)
        self.ai_chat_text.delete(1.0, tk.END)
        self.ai_chat_text.configure(state=tk.DISABLED)
        self.after(100, lambda: self._ai_show_response(get_ai_response("hello"), is_greeting=True))

    # ══════════════════════════════════════════════════════════════════════
    # TAB: PASSWORD GENERATOR
    # ══════════════════════════════════════════════════════════════════════
    def _tab_pwgen(self, parent):
        tk.Label(parent, text="  🎲  PASSWORD GENERATOR",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#AA44FF",
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Cryptographically secure passwords — copy & use",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg="#AA44FF", height=2).pack(fill=tk.X)
        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=16, pady=12); ctrl.pack(fill=tk.X)
        # Length slider
        lr = tk.Frame(ctrl, bg=T["BG_CARD"]); lr.pack(fill=tk.X, pady=4)
        tk.Label(lr, text="Length:", font=("Consolas",9,"bold"), bg=T["BG_CARD"],
                 fg=T["CYAN"], width=10, anchor="w").pack(side=tk.LEFT)
        self.pwgen_len = tk.IntVar(value=20)
        tk.Scale(lr, from_=8, to=64, orient=tk.HORIZONTAL, variable=self.pwgen_len,
                 bg=T["BG_CARD"], fg=T["CYAN"], troughcolor=T["BG_ELEVATED"],
                 highlightthickness=0, length=280, font=("Consolas",8),
                 command=lambda v: self._pwgen_generate()).pack(side=tk.LEFT)
        tk.Label(lr, textvariable=self.pwgen_len, font=("Consolas",13,"bold"),
                 bg=T["BG_CARD"], fg="#AA44FF", width=3).pack(side=tk.LEFT, padx=8)
        # Options
        or_ = tk.Frame(ctrl, bg=T["BG_CARD"]); or_.pack(fill=tk.X, pady=4)
        self.pwgen_upper   = tk.BooleanVar(value=True)
        self.pwgen_lower   = tk.BooleanVar(value=True)
        self.pwgen_digits  = tk.BooleanVar(value=True)
        self.pwgen_symbols = tk.BooleanVar(value=True)
        self.pwgen_ambig   = tk.BooleanVar(value=False)
        for txt,var in [("A-Z",self.pwgen_upper),("a-z",self.pwgen_lower),
                         ("0-9",self.pwgen_digits),("!@#",self.pwgen_symbols),
                         ("No ambiguous",self.pwgen_ambig)]:
            tk.Checkbutton(or_, text=txt, variable=var, font=("Consolas",9),
                          bg=T["BG_CARD"], fg=T["TEXT_MID"], selectcolor=T["BG_ELEVATED"],
                          activebackground=T["BG_CARD"],
                          command=self._pwgen_generate).pack(side=tk.LEFT, padx=10)
        # Password display
        pd = tk.Frame(parent, bg=T["BG_DEEP"], padx=12, pady=10); pd.pack(fill=tk.X)
        pb = tk.Frame(pd, bg="#AA44FF", padx=2, pady=2); pb.pack(fill=tk.X)
        pi = tk.Frame(pb, bg=T["BG_DEEP"]); pi.pack(fill=tk.X)
        self.pwgen_var = tk.StringVar(value="Click GENERATE")
        tk.Label(pi, textvariable=self.pwgen_var, font=("Consolas",16,"bold"),
                 bg=T["BG_DEEP"], fg="#AA44FF", padx=16, pady=14,
                 wraplength=880, justify="left").pack(fill=tk.X)
        # Buttons
        br = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); br.pack(fill=tk.X)
        tk.Button(br, text="🎲 GENERATE", font=("Consolas",11,"bold"),
                  bg="#AA44FF", fg="white", relief=tk.FLAT, cursor="hand2",
                  padx=20, pady=8, command=self._pwgen_generate).pack(side=tk.LEFT)
        tk.Button(br, text="📋 COPY", font=("Consolas",10,"bold"),
                  bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=16, pady=8, command=self._pwgen_copy).pack(side=tk.LEFT, padx=8)
        # Strength
        sf = tk.Frame(parent, bg=T["BG_CARD"], padx=16, pady=12); sf.pack(fill=tk.X)
        tk.Label(sf, text="STRENGTH:", font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"], fg=T["CYAN"]).pack(anchor="w")
        self.pwgen_str_canvas = tk.Canvas(sf, bg=T["BG_ELEVATED"], height=20,
                                           highlightthickness=0)
        self.pwgen_str_canvas.pack(fill=tk.X, pady=4)
        ir = tk.Frame(sf, bg=T["BG_CARD"]); ir.pack(fill=tk.X)
        self.pwgen_str_lbl   = tk.Label(ir, text="--", font=("Consolas",10,"bold"),
                                         bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.pwgen_str_lbl.pack(side=tk.LEFT)
        self.pwgen_crack_lbl = tk.Label(ir, text="", font=("Consolas",9),
                                         bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.pwgen_crack_lbl.pack(side=tk.LEFT, padx=16)
        # Batch
        bf = tk.Frame(parent, bg=T["BG_DEEP"], padx=12, pady=8); bf.pack(fill=tk.BOTH, expand=True)
        bh = tk.Frame(bf, bg=T["BG_DEEP"]); bh.pack(fill=tk.X)
        tk.Label(bh, text="BATCH (10 passwords):", font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"], fg=T["CYAN"]).pack(side=tk.LEFT)
        tk.Button(bh, text="⚡ GENERATE 10", font=("Consolas",8), bg=T["BG_ELEVATED"],
                  fg=T["CYAN"], relief=tk.FLAT, cursor="hand2", padx=8, pady=4,
                  command=self._pwgen_batch).pack(side=tk.LEFT, padx=8)
        self.pwgen_batch_text = tk.Text(bf, font=("Consolas",10), height=8,
                                         bg=T["LOG_BG"], fg="#AA44FF", relief=tk.FLAT,
                                         padx=10, pady=8, state=tk.DISABLED)
        self.pwgen_batch_text.pack(fill=tk.BOTH, expand=True, pady=(4,0))
        self._pwgen_generate()

    def _pwgen_build_charset(self):
        ch = ""
        if self.pwgen_upper.get():   ch += string.ascii_uppercase
        if self.pwgen_lower.get():   ch += string.ascii_lowercase
        if self.pwgen_digits.get():  ch += string.digits
        if self.pwgen_symbols.get(): ch += "!@#$%^&*()-_=+[]{}|;:,.<>?"
        if self.pwgen_ambig.get():
            for c in "0O1lI": ch = ch.replace(c,"")
        return ch or (string.ascii_letters + string.digits)

    def _pwgen_generate(self):
        length = self.pwgen_len.get()
        chars  = self._pwgen_build_charset()
        pw     = "".join(secrets.choice(chars) for _ in range(length))
        self.pwgen_var.set(pw)
        s = analyze_pw_strength(pw)
        color = s.get("color", T["CYAN"])
        self.pwgen_str_lbl.configure(text=s["label"] + "  (" + str(s["score"]) + "/100)", fg=color)
        self.pwgen_crack_lbl.configure(text="Crack: " + s.get("crack_time","?"))
        c = self.pwgen_str_canvas; c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 500
        bw = int(w * s["score"] / 100)
        c.create_rectangle(0, 0, bw, 20, fill=color, outline="")
        c.create_text(min(bw//2+10,w//2), 10, text=str(s["score"])+"%",
                      font=("Consolas",8,"bold"), fill=T["BG_DEEP"])

    def _pwgen_copy(self):
        pw = self.pwgen_var.get()
        if pw and "Click" not in pw:
            self.clipboard_clear(); self.clipboard_append(pw)
            self._set_status("Copied! " + str(len(pw)) + " chars — use it now!")

    def _pwgen_batch(self):
        chars = self._pwgen_build_charset()
        length = self.pwgen_len.get()
        pws = ["".join(secrets.choice(chars) for _ in range(length)) for _ in range(10)]
        self.pwgen_batch_text.configure(state=tk.NORMAL)
        self.pwgen_batch_text.delete(1.0, tk.END)
        for i, pw in enumerate(pws, 1):
            s = analyze_pw_strength(pw)
            self.pwgen_batch_text.insert(tk.END,
                str(i).rjust(2) + ". " + pw + "  [" + s["label"] + "]\n")
        self.pwgen_batch_text.configure(state=tk.DISABLED)



    # ══════════════════════════════════════════════════════════════════════
    # TAB: NMAP GUI SCANNER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_nmap(self, parent):
        tk.Label(parent, text="  🗺  NMAP GUI SCANNER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Port scan, OS detect, version scan — GUI wrapper for nmap",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["CYAN"], height=2).pack(fill=tk.X)

        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Label(ctrl, text="Target:", font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"], fg=T["CYAN"], width=8).pack(side=tk.LEFT)
        self.nmap_target = tk.StringVar(value="192.168.1.1")
        tb = tk.Frame(ctrl, bg=T["CYAN"], padx=1, pady=1)
        tb.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Entry(tb, textvariable=self.nmap_target, font=("Consolas",11),
                 bg=T["BG_DEEP"], fg=T["CYAN"], insertbackground=T["CYAN"],
                 relief=tk.FLAT, bd=5).pack(fill=tk.X)

        self.nmap_preset = tk.StringVar(value="Quick Scan")
        def _preset_changed(v):
            self.nmap_flags_var.set(NMAP_PRESETS.get(v, "-T4 -F"))
        tk.OptionMenu(ctrl, self.nmap_preset, *list(NMAP_PRESETS.keys()),
                      command=_preset_changed).pack(side=tk.LEFT, padx=6)
        self.nmap_flags_var = tk.StringVar(value="-T4 -F")
        tk.Label(ctrl, text="Flags:", font=("Consolas",8),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(8,4))
        tk.Entry(ctrl, textvariable=self.nmap_flags_var, font=("Consolas",9),
                 bg=T["BG_ELEVATED"], fg=T["CYAN"], insertbackground=T["CYAN"],
                 relief=tk.FLAT, bd=3, width=18).pack(side=tk.LEFT)
        self.btn_nmap = tk.Button(ctrl, text="▶ SCAN", font=("Consolas",10,"bold"),
                  bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=6, command=self._nmap_run)
        self.btn_nmap.pack(side=tk.LEFT, padx=8)
        tk.Button(ctrl, text="⬛ STOP", font=("Consolas",9),
                  bg=T["BG_ELEVATED"], fg=T["ORANGE"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=6, command=self._nmap_stop).pack(side=tk.LEFT)

        split = tk.Frame(parent, bg=T["BG_DEEP"])
        split.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        left = tk.Frame(split, bg=T["BG_DEEP"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(left, text="OUTPUT", font=("Consolas",8,"bold"),
                 bg=T["BG_DEEP"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        self.nmap_output = tk.Text(left, font=("Consolas",9), bg=T["LOG_BG"],
                                    fg=T["GREEN"], relief=tk.FLAT, padx=8, pady=6,
                                    state=tk.DISABLED, wrap=tk.NONE)
        nb_vsb = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.nmap_output.yview)
        nb_hsb = ttk.Scrollbar(left, orient=tk.HORIZONTAL, command=self.nmap_output.xview)
        self.nmap_output.configure(yscrollcommand=nb_vsb.set, xscrollcommand=nb_hsb.set)
        nb_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        nb_hsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.nmap_output.pack(fill=tk.BOTH, expand=True)
        self.nmap_output.tag_configure("open",   foreground=T["RED"])
        self.nmap_output.tag_configure("info",   foreground=T["CYAN"])
        self.nmap_output.tag_configure("warn",   foreground=T["ORANGE"])
        self.nmap_output.tag_configure("good",   foreground=T["GREEN"])
        self.nmap_output.tag_configure("normal", foreground=T["TEXT_MID"])

        right = tk.Frame(split, bg=T["BG_CARD"], width=320)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(8,0))
        right.pack_propagate(False)
        tk.Label(right, text="OPEN PORTS", font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"], fg=T["RED"], anchor="w", padx=8).pack(fill=tk.X, pady=(6,2))
        cols = ("Port", "Proto", "Service", "Risk")
        self.nmap_tree = ttk.Treeview(right, columns=cols, show="headings", height=18)
        for col, w in zip(cols, [60, 55, 140, 65]):
            self.nmap_tree.heading(col, text=col)
            self.nmap_tree.column(col, width=w, anchor="w")
        self.nmap_tree.tag_configure("HIGH",   foreground=T["RED"])
        self.nmap_tree.tag_configure("MEDIUM", foreground=T["ORANGE"])
        self.nmap_tree.tag_configure("LOW",    foreground=T["GREEN"])
        vsb2 = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.nmap_tree.yview)
        self.nmap_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side=tk.RIGHT, fill=tk.Y)
        self.nmap_tree.pack(fill=tk.BOTH, expand=True, padx=4)
        self.nmap_summary = tk.Label(right, text="", font=("Consolas",8),
                                      bg=T["BG_CARD"], fg=T["TEXT_DIM"],
                                      anchor="w", padx=8, pady=4)
        self.nmap_summary.pack(fill=tk.X)
        self._nmap_proc = None
        self.after(500, self._nmap_check)

    def _nmap_check(self):
        if not nmap_available():
            self._nmap_log("[!] Nmap not found. Install: https://nmap.org/download.html\n", "warn")
            self._nmap_log("[*] Install karein phir app restart karein\n", "info")
        else:
            self._nmap_log("[+] Nmap detected and ready!\n", "good")
            self._nmap_log("[*] Target enter karein aur SCAN dabao\n", "info")

    def _nmap_log(self, msg, tag="normal"):
        self.nmap_output.configure(state=tk.NORMAL)
        self.nmap_output.insert(tk.END, msg, tag)
        self.nmap_output.see(tk.END)
        self.nmap_output.configure(state=tk.DISABLED)

    def _nmap_run(self):
        self.btn_nmap.configure(state=tk.DISABLED, text="◉ SCANNING...")
        self.nmap_output.configure(state=tk.NORMAL)
        self.nmap_output.delete(1.0, tk.END)
        self.nmap_output.configure(state=tk.DISABLED)
        for r in self.nmap_tree.get_children():
            self.nmap_tree.delete(r)
        target = self.nmap_target.get()
        flags  = self.nmap_flags_var.get()
        threading.Thread(target=self._nmap_bg, args=(target, flags), daemon=True).start()

    def _nmap_bg(self, target, flags):
        def _cb(line):
            tag = "open" if ("open" in line.lower() and "/tcp" in line) else \
                  "warn" if ("error" in line.lower() or "[!]" in line) else \
                  "info" if "nmap scan" in line.lower() else "normal"
            self._ui( lambda m=line, t=tag: self._nmap_log(m, t))
        result = run_nmap(target, flags, output_cb=_cb)
        self._ui( lambda: self._nmap_show(result))

    def _nmap_show(self, r):
        self.btn_nmap.configure(state=tk.NORMAL, text="▶ SCAN")
        for p in r.get("open_ports", []):
            sev = p.get("risk", "LOW")
            self.nmap_tree.insert("", "end",
                values=(p["port"], p["proto"], p["service"][:20], sev),
                tags=(sev,))
        n = r.get("port_count", 0)
        t = r.get("elapsed", 0)
        os_s = r.get("os", "")
        summary = f"Ports: {n}  |  Time: {t}s"
        if os_s:
            summary += f"  |  OS: {os_s[:28]}"
        self.nmap_summary.configure(text=summary)

    def _nmap_stop(self):
        if self._nmap_proc:
            try: self._nmap_proc.terminate()
            except Exception: pass
        self.btn_nmap.configure(state=tk.NORMAL, text="▶ SCAN")
        self._nmap_log("[*] Scan stopped\n", "warn")

    # ══════════════════════════════════════════════════════════════════════
    # TAB: WINDOWS DEFENDER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_defender(self, parent):
        tk.Label(parent, text="  🛡  WINDOWS DEFENDER INTEGRATION",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["GREEN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Real-time protection status · Scan control · Threat history",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["GREEN"], height=2).pack(fill=tk.X)

        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔄 REFRESH STATUS", font=("Consolas",10,"bold"),
                  bg=T["GREEN_DIM"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=6, command=self._def_refresh).pack(side=tk.LEFT)
        tk.Button(ctrl, text="⚡ QUICK SCAN", font=("Consolas",9,"bold"),
                  bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=10, pady=6,
                  command=lambda: self._def_scan("Quick")).pack(side=tk.LEFT, padx=4)
        tk.Button(ctrl, text="🔍 FULL SCAN", font=("Consolas",9,"bold"),
                  bg=T["ORANGE"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=10, pady=6,
                  command=lambda: self._def_scan("Full")).pack(side=tk.LEFT, padx=4)
        tk.Button(ctrl, text="🔁 UPDATE SIGS", font=("Consolas",9),
                  bg=T["BG_ELEVATED"], fg=T["GREEN"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=6, command=self._def_update).pack(side=tk.LEFT, padx=4)

        body = tk.Frame(parent, bg=T["BG_DEEP"])
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        left = tk.Frame(body, bg=T["BG_DEEP"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        grid = tk.Frame(left, bg=T["BG_DEEP"]); grid.pack(fill=tk.X)
        self.def_status_widgets = {}
        protections = [
            ("Real-Time Protection", "realtime"),
            ("Antivirus",            "antivirus"),
            ("Anti-Spyware",         "antispyware"),
            ("Behavior Monitor",     "behavior"),
            ("Network Protection",   "network_protect"),
            ("On-Access Scan",       "on_access"),
        ]
        for idx, (label, key) in enumerate(protections):
            row = idx // 2; col = idx % 2
            card = tk.Frame(grid, bg=T["BG_CARD"], padx=14, pady=10)
            card.grid(row=row, column=col, padx=4, pady=4, sticky="ew")
            grid.columnconfigure(col, weight=1)
            tk.Label(card, text=label, font=("Consolas",8),
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
            indicator = tk.Label(card, text="◉ CHECKING...",
                                  font=("Consolas",10,"bold"),
                                  bg=T["BG_CARD"], fg=T["TEXT_DIM"], anchor="w")
            indicator.pack(fill=tk.X)
            self.def_status_widgets[key] = indicator

        info_row = tk.Frame(left, bg=T["BG_CARD"], padx=14, pady=10)
        info_row.pack(fill=tk.X, pady=(6,0))
        self.def_updated_lbl = tk.Label(info_row, text="Last Update: --",
                                         font=("Consolas",9), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.def_updated_lbl.pack(side=tk.LEFT)
        self.def_scan_lbl = tk.Label(info_row, text="",
                                      font=("Consolas",9), bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.def_scan_lbl.pack(side=tk.LEFT, padx=20)

        right = tk.Frame(body, bg=T["BG_DEEP"], width=360)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(10,0))
        right.pack_propagate(False)
        tk.Label(right, text="THREAT HISTORY", font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"], fg=T["RED"], anchor="w").pack(fill=tk.X, pady=(0,4))
        cols = ("Threat Name", "Detected", "Fixed")
        self.def_threats_tree = ttk.Treeview(right, columns=cols, show="headings", height=8)
        for col, w in zip(cols, [190, 100, 50]):
            self.def_threats_tree.heading(col, text=col)
            self.def_threats_tree.column(col, width=w, anchor="w")
        self.def_threats_tree.tag_configure("fixed",   foreground=T["GREEN"])
        self.def_threats_tree.tag_configure("unfixed", foreground=T["RED"])
        self.def_threats_tree.pack(fill=tk.X)
        tk.Label(right, text="SCAN LOG", font=("Consolas",9,"bold"),
                 bg=T["BG_DEEP"], fg=T["CYAN"], anchor="w").pack(fill=tk.X, pady=(10,4))
        self.def_log = tk.Text(right, font=("Consolas",8), bg=T["LOG_BG"],
                                fg=T["TEXT_MID"], relief=tk.FLAT, padx=8, pady=6,
                                state=tk.DISABLED, wrap=tk.WORD)
        self.def_log.pack(fill=tk.BOTH, expand=True)
        self.def_log.tag_configure("good", foreground=T["GREEN"])
        self.def_log.tag_configure("warn", foreground=T["ORANGE"])
        self.def_log.tag_configure("info", foreground=T["CYAN"])
        self.after(400, self._def_refresh)

    def _def_refresh(self):
        self._def_log("[*] Checking Windows Defender status...\n", "info")
        threading.Thread(target=self._def_refresh_bg, daemon=True).start()

    def _def_refresh_bg(self):
        status  = get_defender_status()
        threats = get_defender_threats()
        self._ui( lambda: self._def_show(status, threats))

    def _def_show(self, s, threats):
        for key, widget in self.def_status_widgets.items():
            val = s.get(key, False)
            widget.configure(text="◉ ENABLED" if val else "◉ DISABLED",
                             fg=T["GREEN"] if val else T["RED"])
        self.def_updated_lbl.configure(text="Last Update: " + s.get("last_updated","?"))
        qs = s.get("quick_scan_age", -1); fs = s.get("full_scan_age", -1)
        scan_txt = ""
        if qs >= 0: scan_txt += f"Quick: {qs}d ago  "
        if fs >= 0: scan_txt += f"Full: {fs}d ago"
        self.def_scan_lbl.configure(text=scan_txt)
        for r in self.def_threats_tree.get_children():
            self.def_threats_tree.delete(r)
        if threats:
            for t in threats:
                tag = "fixed" if t.get("fixed") else "unfixed"
                self.def_threats_tree.insert("", "end",
                    values=(t["name"][:30], t["time"][:10],
                            "✓" if t.get("fixed") else "✗"),
                    tags=(tag,))
        else:
            self.def_threats_tree.insert("", "end",
                values=("No recent threats", "", ""), tags=("fixed",))
        self._def_log("[+] Status refreshed\n", "good")

    def _def_scan(self, scan_type):
        self._def_log(f"[*] Starting {scan_type} scan...\n", "info")
        def _bg():
            run_defender_scan(scan_type,
                output_cb=lambda m: self._ui( lambda msg=m: self._def_log(msg, "info")))
        threading.Thread(target=_bg, daemon=True).start()

    def _def_update(self):
        self._def_log("[*] Updating signatures...\n", "info")
        def _bg():
            update_defender_signatures(
                output_cb=lambda m: self._ui( lambda msg=m: self._def_log(msg, "good")))
        threading.Thread(target=_bg, daemon=True).start()

    def _def_log(self, msg, tag="info"):
        self.def_log.configure(state=tk.NORMAL)
        self.def_log.insert(tk.END, msg, tag)
        self.def_log.see(tk.END)
        self.def_log.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: STEGANOGRAPHY DETECTOR
    # ══════════════════════════════════════════════════════════════════════
    def _tab_stego(self, parent):
        tk.Label(parent, text="  👁  STEGANOGRAPHY DETECTOR",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg="#AA44FF",
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Images mein hidden data detect karo — LSB, EOF, EXIF analysis",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg="#AA44FF", height=2).pack(fill=tk.X)

        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        self.stego_path = tk.StringVar()
        pb = tk.Frame(ctrl, bg="#AA44FF", padx=1, pady=1)
        pb.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Entry(pb, textvariable=self.stego_path, font=("Consolas",10),
                 bg=T["BG_DEEP"], fg="#AA44FF", insertbackground="#AA44FF",
                 relief=tk.FLAT, bd=5).pack(fill=tk.X)

        def _pick_file():
            p = filedialog.askopenfilename(
                filetypes=[("Images","*.jpg *.jpeg *.png *.bmp *.gif"),("All","*.*")])
            if p: self.stego_path.set(p)
        def _pick_folder():
            p = filedialog.askdirectory()
            if p: self.stego_path.set(p)

        tk.Button(ctrl, text="📄 FILE", font=("Consolas",9), bg=T["BG_ELEVATED"],
                  fg="#AA44FF", relief=tk.FLAT, cursor="hand2",
                  padx=8, command=_pick_file).pack(side=tk.LEFT, padx=4)
        tk.Button(ctrl, text="📂 FOLDER", font=("Consolas",9), bg=T["BG_ELEVATED"],
                  fg="#AA44FF", relief=tk.FLAT, cursor="hand2",
                  padx=8, command=_pick_folder).pack(side=tk.LEFT, padx=2)
        self.btn_stego = tk.Button(ctrl, text="🔍 ANALYZE", font=("Consolas",10,"bold"),
                  bg="#AA44FF", fg="white", relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=6, command=self._stego_scan)
        self.btn_stego.pack(side=tk.LEFT, padx=8)

        self.stego_verdict = tk.Label(parent,
                                       text="Select file/folder and click ANALYZE",
                                       font=("Consolas",10,"bold"), bg=T["BG_ELEVATED"],
                                       fg=T["TEXT_DIM"], anchor="w", padx=14, pady=8)
        self.stego_verdict.pack(fill=tk.X)

        split = tk.Frame(parent, bg=T["BG_DEEP"])
        split.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        left = tk.Frame(split, bg=T["BG_DEEP"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.stego_text = tk.Text(left, font=("Consolas",9), bg=T["LOG_BG"],
                                   fg=T["TEXT_MID"], relief=tk.FLAT, padx=10, pady=8,
                                   state=tk.DISABLED, wrap=tk.WORD)
        sv = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.stego_text.yview)
        self.stego_text.configure(yscrollcommand=sv.set)
        sv.pack(side=tk.RIGHT, fill=tk.Y)
        self.stego_text.pack(fill=tk.BOTH, expand=True)
        self.stego_text.tag_configure("crit", foreground=T["RED"], font=("Consolas",9,"bold"))
        self.stego_text.tag_configure("warn", foreground=T["ORANGE"])
        self.stego_text.tag_configure("good", foreground=T["GREEN"])
        self.stego_text.tag_configure("head", foreground="#AA44FF", font=("Consolas",9,"bold"))
        self.stego_text.tag_configure("info", foreground=T["CYAN"])

        right = tk.Frame(split, bg=T["BG_CARD"], width=260, padx=12, pady=12)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(8,0))
        right.pack_propagate(False)
        tk.Label(right, text="WHAT IS STEGANOGRAPHY?",
                 font=("Consolas",8,"bold"), bg=T["BG_CARD"],
                 fg="#AA44FF", anchor="w").pack(fill=tk.X)
        tk.Frame(right, bg="#AA44FF", height=1).pack(fill=tk.X, pady=4)
        info_lines = [
            "Hiding data INSIDE innocent files",
            "",
            "TECHNIQUES:",
            "• LSB bit substitution",
            "• EOF data injection",
            "• EXIF field hiding",
            "• Color palette tricks",
            "",
            "USED FOR:",
            "• Covert communication",
            "• Data exfiltration",
            "• Malware C2 channels",
            "",
            "RED FLAGS:",
            "• Bytes after EOF marker",
            "• LSB ratio near 50%",
            "• Oversized image files",
            "• Hidden text strings",
        ]
        for line in info_lines:
            tk.Label(right, text=line, font=("Segoe UI",8), bg=T["BG_CARD"],
                     fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)

    def _stego_scan(self):
        path = self.stego_path.get().strip()
        if not path: return
        self.btn_stego.configure(state=tk.DISABLED, text="◉ SCANNING...")
        self.stego_text.configure(state=tk.NORMAL)
        self.stego_text.delete(1.0, tk.END)
        self.stego_text.configure(state=tk.DISABLED)
        threading.Thread(target=self._stego_bg, args=(path,), daemon=True).start()

    def _stego_bg(self, path):
        import os as _os
        if os.path.isdir(path):
            results = scan_folder_stego(path,
                progress_cb=lambda m: self._ui(
                    lambda msg=m: self.stego_verdict.configure(text=msg)))
            self._ui( lambda: self._stego_show_batch(results, path))
        else:
            result = detect_steganography(path)
            self._ui( lambda: self._stego_show_single(result))

    def _stego_show_single(self, r):
        import os as _os
        self.btn_stego.configure(state=tk.NORMAL, text="🔍 ANALYZE")
        sus   = r.get("suspicious", False)
        risk  = r.get("risk", "LOW")
        color = T["RED"] if risk=="HIGH" else T["ORANGE"] if risk=="MEDIUM" else T["GREEN"]
        v_txt = ("SUSPICIOUS — Hidden data possible!" if sus else "No steganography detected")
        self.stego_verdict.configure(text=v_txt + "  |  Risk: " + risk, fg=color)
        self.stego_text.configure(state=tk.NORMAL)
        fname = os.path.basename(r.get("file","?"))
        self.stego_text.insert(tk.END, "File: " + fname + "\n\n", "head")
        for ind in r.get("indicators", []):
            tag = "crit" if "🚨" in ind else "warn" if "⚠" in ind else "good"
            self.stego_text.insert(tk.END, ind + "\n", tag)
        if r.get("error"):
            self.stego_text.insert(tk.END, "Error: " + r["error"] + "\n", "warn")
        self.stego_text.configure(state=tk.DISABLED)

    def _stego_show_batch(self, results, folder):
        import os as _os
        self.btn_stego.configure(state=tk.NORMAL, text="🔍 ANALYZE")
        count = len(results)
        color = T["RED"] if count > 0 else T["GREEN"]
        self.stego_verdict.configure(
            text=f"Folder scan: {count} suspicious file(s) — {os.path.basename(folder)}",
            fg=color)
        self.stego_text.configure(state=tk.NORMAL)
        self.stego_text.delete(1.0, tk.END)
        if results:
            for r in results:
                self.stego_text.insert(tk.END,
                    "SUSPICIOUS: " + os.path.basename(r.get("file","?")) + "\n", "crit")
                for ind in r.get("indicators", []):
                    self.stego_text.insert(tk.END, "   " + ind + "\n", "warn")
                self.stego_text.insert(tk.END, "\n")
        else:
            self.stego_text.insert(tk.END,
                "No steganography detected in any files\n", "good")
        self.stego_text.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: ENCRYPTED CHAT
    # ══════════════════════════════════════════════════════════════════════
    def _tab_echat(self, parent):
        tk.Label(parent, text="  🔐  ENCRYPTED MESSAGING",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Messages ko encrypt/decrypt karo — key share karke secure chat",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["CYAN"], height=2).pack(fill=tk.X)

        key_row = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8)
        key_row.pack(fill=tk.X)
        tk.Label(key_row, text="🔑 Secret Key:", font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"], fg=T["CYAN"], width=14).pack(side=tk.LEFT)
        self.echat_key = tk.StringVar()
        kb = tk.Frame(key_row, bg=T["CYAN"], padx=1, pady=1)
        kb.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.echat_key_entry = tk.Entry(kb, textvariable=self.echat_key,
                                         font=("Consolas",11), bg=T["BG_DEEP"],
                                         fg=T["CYAN"], insertbackground=T["CYAN"],
                                         relief=tk.FLAT, bd=5, show="●")
        self.echat_key_entry.pack(fill=tk.X)

        def _toggle_show():
            cur = self.echat_key_entry.cget("show")
            self.echat_key_entry.configure(show="" if cur == "●" else "●")
        def _rand_key():
            import secrets as _sec
            chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%"
            k = "".join(secrets.choice(chars) for _ in range(32))
            self.echat_key.set(k)
            self._echat_log("sys", "Random key generated — share it securely with partner!")

        tk.Button(key_row, text="👁 SHOW", font=("Consolas",8), bg=T["BG_ELEVATED"],
                  fg=T["TEXT_DIM"], relief=tk.FLAT, cursor="hand2",
                  padx=8, command=_toggle_show).pack(side=tk.LEFT, padx=6)
        tk.Button(key_row, text="🎲 RANDOM", font=("Consolas",9), bg=T["BG_ELEVATED"],
                  fg=T["CYAN"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=4, command=_rand_key).pack(side=tk.LEFT, padx=4)

        cf = tk.Frame(parent, bg=T["BG_DEEP"])
        cf.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self.echat_display = tk.Text(cf, font=("Consolas",9), bg="#070710",
                                      fg=T["TEXT_MID"], relief=tk.FLAT, padx=12, pady=8,
                                      state=tk.DISABLED, wrap=tk.WORD)
        ecsb = ttk.Scrollbar(cf, orient=tk.VERTICAL, command=self.echat_display.yview)
        self.echat_display.configure(yscrollcommand=ecsb.set)
        ecsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.echat_display.pack(fill=tk.BOTH, expand=True)
        self.echat_display.tag_configure("sent",   foreground=T["CYAN"],  font=("Consolas",9,"bold"))
        self.echat_display.tag_configure("recv",   foreground=T["GREEN"], font=("Consolas",9,"bold"))
        self.echat_display.tag_configure("cipher", foreground=T["ORANGE"],font=("Consolas",8))
        self.echat_display.tag_configure("plain",  foreground=T["TEXT_MID"])
        self.echat_display.tag_configure("sys",    foreground="#AA44FF")
        self.echat_display.tag_configure("error",  foreground=T["RED"])

        ia = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8)
        ia.pack(fill=tk.X)
        self.echat_name = tk.StringVar(value="You")
        tk.Entry(ia, textvariable=self.echat_name, font=("Consolas",9),
                 bg=T["BG_ELEVATED"], fg=T["CYAN"], insertbackground=T["CYAN"],
                 relief=tk.FLAT, bd=3, width=10).pack(side=tk.LEFT)
        tk.Label(ia, text=":", font=("Consolas",12,"bold"),
                 bg=T["BG_CARD"], fg=T["CYAN"]).pack(side=tk.LEFT)
        ib = tk.Frame(ia, bg=T["CYAN"], padx=1, pady=1)
        ib.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        self.echat_input = tk.Entry(ib, font=("Consolas",11), bg=T["BG_DEEP"],
                                     fg=T["TEXT_MID"], insertbackground=T["CYAN"],
                                     relief=tk.FLAT, bd=6)
        self.echat_input.pack(fill=tk.X)
        self.echat_input.bind("<Return>", lambda e: self._echat_send())
        tk.Button(ia, text="🔒 SEND", font=("Consolas",10,"bold"),
                  bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=7, command=self._echat_send).pack(side=tk.LEFT)

        dr = tk.Frame(parent, bg=T["BG_ELEVATED"], padx=12, pady=6)
        dr.pack(fill=tk.X)
        tk.Label(dr, text="DECRYPT:", font=("Consolas",8,"bold"),
                 bg=T["BG_ELEVATED"], fg=T["ORANGE"]).pack(side=tk.LEFT)
        self.echat_dec_input = tk.Entry(dr, font=("Consolas",8), bg=T["BG_DEEP"],
                                         fg=T["ORANGE"], insertbackground=T["ORANGE"],
                                         relief=tk.FLAT, bd=3)
        self.echat_dec_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6)
        tk.Button(dr, text="🔓 DECRYPT", font=("Consolas",9),
                  bg=T["ORANGE"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=4, command=self._echat_decrypt).pack(side=tk.LEFT)

        self._echat_log("sys", "Encrypted Chat ready!")
        self._echat_log("sys", "1. Key daalo (ya RANDOM dabao)")
        self._echat_log("sys", "2. Message likhko aur SEND")
        self._echat_log("sys", "3. Encrypted text copy karke share karo!")

    def _echat_send(self):
        msg    = self.echat_input.get().strip()
        key    = self.echat_key.get()
        sender = self.echat_name.get() or "You"
        if not msg: return
        if not key:
            self._echat_log("error", "Key enter karein pehle!"); return
        self.echat_input.delete(0, tk.END)
        result = encrypt_message(msg, key)
        ct = result.get("ciphertext", "")
        ts = result.get("timestamp", "")
        self._echat_log("sent",   "[" + ts + "] " + sender + " (sending):")
        self._echat_log("plain",  "   Plain:  " + msg)
        self._echat_log("cipher", "   Enc:    " + ct[:70] + "...")
        self._echat_log("plain",  "   Hash:   " + result.get("hash","") + "\n")
        self.echat_dec_input.delete(0, tk.END)
        self.echat_dec_input.insert(0, ct)

    def _echat_decrypt(self):
        ct  = self.echat_dec_input.get().strip()
        key = self.echat_key.get()
        if not ct: return
        if not key:
            self._echat_log("error", "Key enter karein pehle!"); return
        result = decrypt_message(ct, key)
        if "error" in result:
            self._echat_log("error", "Decrypt failed: " + result["error"])
        else:
            self._echat_log("recv",  "Decrypted message:")
            self._echat_log("plain", "   " + result.get("plaintext", "") + "\n")

    def _echat_log(self, tag, msg):
        self.echat_display.configure(state=tk.NORMAL)
        self.echat_display.insert(tk.END, msg + "\n", tag)
        self.echat_display.see(tk.END)
        self.echat_display.configure(state=tk.DISABLED)


    # ══════════════════════════════════════════════════════════════════════
    # TAB: LIVE PACKET ANALYZER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_packets(self, parent):
        tk.Label(parent, text="  📡  LIVE NETWORK ANALYZER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["ORANGE"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Live connections · DNS cache · Bandwidth per process",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["ORANGE"], height=2).pack(fill=tk.X)

        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔄 REFRESH", font=("Consolas",10,"bold"),
                  bg=T["ORANGE"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=6, command=self._pkt_refresh).pack(side=tk.LEFT)
        self.pkt_auto_var = tk.BooleanVar(value=False)
        tk.Checkbutton(ctrl, text="AUTO 3s", font=("Consolas",9),
                       variable=self.pkt_auto_var, bg=T["BG_CARD"], fg=T["ORANGE"],
                       selectcolor=T["BG_ELEVATED"], activebackground=T["BG_CARD"],
                       command=self._pkt_toggle).pack(side=tk.LEFT, padx=8)
        self.pkt_status = tk.Label(ctrl, text="", font=("Consolas",8),
                                    bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.pkt_status.pack(side=tk.LEFT, padx=8)
        tk.Button(ctrl, text="🔍 DNS CACHE", font=("Consolas",9),
                  bg=T["BG_ELEVATED"], fg=T["CYAN"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=6, command=self._pkt_dns).pack(side=tk.RIGHT)

        nb_pkt = ttk.Notebook(parent); nb_pkt.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Connections tab
        cf = tk.Frame(nb_pkt, bg=T["BG_DEEP"]); nb_pkt.add(cf, text=" 🌐 Live Connections ")
        cols = ("Process", "Local", "Remote", "Status", "Proto", "⚠")
        self.pkt_tree = ttk.Treeview(cf, columns=cols, show="headings")
        for col, w in zip(cols, [150, 165, 175, 100, 50, 30]):
            self.pkt_tree.heading(col, text=col)
            self.pkt_tree.column(col, width=w, anchor="w")
        self.pkt_tree.tag_configure("suspicious", foreground=T["RED"], font=("Consolas",9,"bold"))
        self.pkt_tree.tag_configure("normal",     foreground=T["TEXT_MID"])
        pvsb = ttk.Scrollbar(cf, orient=tk.VERTICAL, command=self.pkt_tree.yview)
        self.pkt_tree.configure(yscrollcommand=pvsb.set)
        pvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.pkt_tree.pack(fill=tk.BOTH, expand=True)

        # Bandwidth tab
        bwf = tk.Frame(nb_pkt, bg=T["BG_DEEP"]); nb_pkt.add(bwf, text=" 📊 Bandwidth ")
        self.bw_canvas = tk.Canvas(bwf, bg=T["BG_DEEP"], highlightthickness=0)
        self.bw_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # DNS tab
        dns_f = tk.Frame(nb_pkt, bg=T["BG_DEEP"]); nb_pkt.add(dns_f, text=" 🔍 DNS Cache ")
        self.dns_text = tk.Text(dns_f, font=("Consolas",10), bg=T["LOG_BG"],
                                 fg=T["GREEN"], relief=tk.FLAT, padx=10, pady=8,
                                 state=tk.DISABLED)
        self.dns_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.after(700, self._pkt_refresh)

    def _pkt_refresh(self):
        threading.Thread(target=self._pkt_bg, daemon=True).start()

    def _pkt_bg(self):
        conns = get_live_connections()
        bw    = get_bandwidth_per_process()
        self._ui( lambda: self._pkt_show(conns, bw))

    def _pkt_show(self, conns, bw):
        for r in self.pkt_tree.get_children(): self.pkt_tree.delete(r)
        suspicious = 0
        for c in conns:
            if c.get("error"): continue
            is_sus = c.get("suspicious", False)
            if is_sus: suspicious += 1
            tag = "suspicious" if is_sus else "normal"
            self.pkt_tree.insert("", "end",
                values=(c.get("process","?"), c.get("local","?"),
                        c.get("remote","?"), c.get("status","?"),
                        c.get("proto","?"), "⚠" if is_sus else ""),
                tags=(tag,))
        ts = datetime.now().strftime("%H:%M:%S")
        self.pkt_status.configure(
            text=f"{len(conns)} connections | {suspicious} suspicious | {ts}")
        # Draw bandwidth bars
        c = self.bw_canvas; c.delete("all")
        c.update_idletasks()
        w = c.winfo_width() or 600; h = c.winfo_height() or 280
        if bw:
            bar_w = max(30, (w - 40) // len(bw))
            max_c = max(p["connections"] for p in bw) or 1
            for i, p in enumerate(bw):
                x     = 20 + i * bar_w
                bh    = int((h - 60) * p["connections"] / max_c)
                color = T["ORANGE"] if p["connections"] > 5 else T["CYAN"]
                c.create_rectangle(x, h-30-bh, x+bar_w-4, h-30, fill=color, outline="")
                c.create_text(x+bar_w//2, h-15, text=p["name"][:10],
                              font=("Consolas",7), fill=T["TEXT_DIM"])
                if bh > 12:
                    c.create_text(x+bar_w//2, h-36-bh,
                                  text=str(p["connections"]),
                                  font=("Consolas",8,"bold"), fill=color)

    def _pkt_dns(self):
        self.dns_text.configure(state=tk.NORMAL)
        self.dns_text.delete(1.0, tk.END)
        domains = capture_dns_queries()
        if domains:
            for d in domains:
                self.dns_text.insert(tk.END, d + "\n")
        else:
            self.dns_text.insert(tk.END,
                "No DNS entries found\n(Run as Administrator for full access)")
        self.dns_text.configure(state=tk.DISABLED)

    def _pkt_toggle(self):
        if self.pkt_auto_var.get():
            self._pkt_auto_tick()

    def _pkt_auto_tick(self):
        if self.pkt_auto_var.get():
            self._pkt_refresh()
            self.after(3000, self._pkt_auto_tick)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: HASH CRACKER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_hashcrack(self, parent):
        tk.Label(parent, text="  🔓  PASSWORD HASH CRACKER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["RED"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  MD5/SHA1/SHA256/NTLM — wordlist attack | Educational only!",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["RED"], height=2).pack(fill=tk.X)

        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=10); ctrl.pack(fill=tk.X)
        tk.Label(ctrl, text="Hash:", font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"], fg=T["RED"], width=6).pack(side=tk.LEFT)
        self.crack_hash_var = tk.StringVar()
        hb = tk.Frame(ctrl, bg=T["RED"], padx=1, pady=1)
        hb.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Entry(hb, textvariable=self.crack_hash_var, font=("Consolas",11),
                 bg=T["BG_DEEP"], fg=T["RED"], insertbackground=T["RED"],
                 relief=tk.FLAT, bd=5).pack(fill=tk.X)

        tk.Label(ctrl, text="Algo:", font=("Consolas",9),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(10,4))
        self.crack_algo = tk.StringVar(value="MD5")
        tk.OptionMenu(ctrl, self.crack_algo, *list(HASH_ALGOS.keys())).pack(side=tk.LEFT)
        self.btn_crack = tk.Button(ctrl, text="⚡ CRACK", font=("Consolas",10,"bold"),
                  bg=T["RED"], fg="white", relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=6, command=self._crack_start)
        self.btn_crack.pack(side=tk.LEFT, padx=8)
        tk.Button(ctrl, text="# IDENTIFY", font=("Consolas",9),
                  bg=T["BG_ELEVATED"], fg=T["ORANGE"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=6, command=self._crack_identify).pack(side=tk.LEFT)

        self.crack_result = tk.Label(parent, text="Enter a hash above and click CRACK",
                                      font=("Consolas",12,"bold"), bg=T["BG_ELEVATED"],
                                      fg=T["TEXT_DIM"], anchor="w", padx=14, pady=10)
        self.crack_result.pack(fill=tk.X)

        split = tk.Frame(parent, bg=T["BG_DEEP"])
        split.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        left = tk.Frame(split, bg=T["BG_DEEP"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(left, text="WORDLIST ATTACK LOG", font=("Consolas",8,"bold"),
                 bg=T["BG_DEEP"], fg=T["RED"], anchor="w").pack(fill=tk.X)
        self.crack_log = tk.Text(left, font=("Consolas",9), bg=T["LOG_BG"],
                                  fg=T["TEXT_MID"], relief=tk.FLAT, padx=8, pady=6,
                                  state=tk.DISABLED, wrap=tk.WORD)
        clsb = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.crack_log.yview)
        self.crack_log.configure(yscrollcommand=clsb.set)
        clsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.crack_log.pack(fill=tk.BOTH, expand=True)
        self.crack_log.tag_configure("found",  foreground=T["GREEN"], font=("Consolas",10,"bold"))
        self.crack_log.tag_configure("trying", foreground=T["TEXT_DIM"])
        self.crack_log.tag_configure("info",   foreground=T["CYAN"])
        self.crack_log.tag_configure("fail",   foreground=T["RED"])

        right = tk.Frame(split, bg=T["BG_CARD"], width=310, padx=12, pady=12)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(8,0))
        right.pack_propagate(False)
        tk.Label(right, text="HASH GENERATOR", font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"], fg=T["CYAN"], anchor="w").pack(fill=tk.X)
        tk.Frame(right, bg=T["CYAN"], height=1).pack(fill=tk.X, pady=4)
        tk.Label(right, text="Input text:", font=("Consolas",8),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        self.hashgen_input = tk.Entry(right, font=("Consolas",10),
                                       bg=T["BG_ELEVATED"], fg=T["GREEN"],
                                       insertbackground=T["GREEN"],
                                       relief=tk.FLAT, bd=5)
        self.hashgen_input.pack(fill=tk.X, pady=4)
        self.hashgen_input.bind("<KeyRelease>", lambda e: self._hashgen_update())
        self._hashgen_vars = {}
        for algo in ["MD5", "SHA1", "SHA256", "NTLM"]:
            row = tk.Frame(right, bg=T["BG_CARD"]); row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=algo + ":", font=("Consolas",7,"bold"),
                     bg=T["BG_CARD"], fg=T["RED"], width=7, anchor="w").pack(side=tk.LEFT)
            var = tk.StringVar(value="--")
            lbl = tk.Label(row, textvariable=var, font=("Consolas",7),
                          bg=T["BG_CARD"], fg=T["TEXT_MID"], anchor="w", wraplength=200)
            lbl.pack(side=tk.LEFT, fill=tk.X, expand=True)
            tk.Button(row, text="📋", font=("Consolas",7), bg=T["BG_ELEVATED"],
                      fg=T["TEXT_DIM"], relief=tk.FLAT, cursor="hand2",
                      command=lambda v=var: (
                          self.clipboard_clear(), self.clipboard_append(v.get()))
                      ).pack(side=tk.RIGHT)
            self._hashgen_vars[algo] = var

        tk.Frame(right, bg=T["BG_ELEVATED"], height=1).pack(fill=tk.X, pady=8)
        tk.Label(right, text="SAMPLE HASHES (test):", font=("Consolas",8,"bold"),
                 bg=T["BG_CARD"], fg=T["ORANGE"], anchor="w").pack(fill=tk.X)
        for pwd in ["password", "admin", "123456", "test"]:
            h = hashlib.md5(pwd.encode()).hexdigest()
            row = tk.Frame(right, bg=T["BG_CARD"]); row.pack(fill=tk.X, pady=1)
            tk.Label(row, text=pwd + ":", font=("Consolas",8),
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"], width=10).pack(side=tk.LEFT)
            tk.Label(row, text=h[:18] + "...", font=("Consolas",7),
                     bg=T["BG_CARD"], fg=T["ORANGE"]).pack(side=tk.LEFT)
            tk.Button(row, text="USE", font=("Consolas",6), bg=T["BG_ELEVATED"],
                      fg=T["RED"], relief=tk.FLAT, cursor="hand2",
                      command=lambda x=h: (
                          self.crack_hash_var.set(x),
                          self.crack_algo.set("MD5"))
                      ).pack(side=tk.RIGHT)

    def _crack_start(self):
        h = self.crack_hash_var.get().strip()
        if not h: return
        self.btn_crack.configure(state=tk.DISABLED, text="◉ CRACKING...")
        self.crack_log.configure(state=tk.NORMAL)
        self.crack_log.delete(1.0, tk.END)
        self.crack_log.configure(state=tk.DISABLED)
        algo = self.crack_algo.get()
        self.crack_result.configure(text="Cracking: " + h[:24] + "...", fg=T["TEXT_DIM"])
        threading.Thread(target=self._crack_bg, args=(h, algo), daemon=True).start()

    def _crack_bg(self, h, algo):
        def _cb(msg):
            self._ui( lambda m=msg: (
                self.crack_log.configure(state=tk.NORMAL),
                self.crack_log.insert(tk.END, m + "\n", "trying"),
                self.crack_log.see(tk.END),
                self.crack_log.configure(state=tk.DISABLED)))
        result = crack_hash(h, algo, BUILTIN_WORDLIST, _cb)
        self._ui( lambda: self._crack_show(result))

    def _crack_show(self, r):
        self.btn_crack.configure(state=tk.NORMAL, text="⚡ CRACK")
        self.crack_log.configure(state=tk.NORMAL)
        if r.get("found"):
            pw = r["password"]; n = r["attempts"]
            self.crack_log.insert(tk.END,
                "\nCRACKED in " + str(n) + " attempts!\nPassword: " + pw + "\n", "found")
            self.crack_result.configure(
                text="CRACKED: '" + pw + "'  (" + r["algo"] + ", " + str(n) + " attempts)",
                fg=T["GREEN"])
        else:
            self.crack_log.insert(tk.END,
                "\nNot found in " + str(r["attempts"]) + " entries\n", "fail")
            self.crack_result.configure(
                text="Not cracked — not in wordlist (" + str(r["attempts"]) + " tried)",
                fg=T["RED"])
        self.crack_log.see(tk.END)
        self.crack_log.configure(state=tk.DISABLED)

    def _crack_identify(self):
        h = self.crack_hash_var.get().strip()
        if not h: return
        t = identify_hash_type(h)
        self.crack_result.configure(
            text="Hash type: " + t + "  (length: " + str(len(h)) + ")",
            fg=T["CYAN"])

    def _hashgen_update(self):
        text = self.hashgen_input.get()
        for algo, var in self._hashgen_vars.items():
            fn = HASH_ALGOS.get(algo)
            if fn:
                try: var.set(fn(text) if text else "--")
                except Exception: var.set("error")

    # ══════════════════════════════════════════════════════════════════════
    # TAB: SOCIAL ENGINEERING TOOLKIT
    # ══════════════════════════════════════════════════════════════════════
    def _tab_soceng(self, parent):
        tk.Label(parent, text="  🎭  SOCIAL ENGINEERING AWARENESS TOOLKIT",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["YELLOW"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Phishing templates · Pretexting scripts · Awareness training",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["YELLOW"], height=2).pack(fill=tk.X)
        tk.Label(parent, text="  EDUCATIONAL PURPOSES ONLY — Do NOT use for actual attacks",
                 font=("Consolas",9,"bold"), bg="#2A1500", fg=T["ORANGE"],
                 anchor="w", padx=14, pady=5).pack(fill=tk.X)

        nb_se = ttk.Notebook(parent); nb_se.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Phishing Templates tab
        pt_f = tk.Frame(nb_se, bg=T["BG_DEEP"])
        nb_se.add(pt_f, text=" 🎣 Phishing Templates ")
        pt_ctrl = tk.Frame(pt_f, bg=T["BG_CARD"], padx=12, pady=8)
        pt_ctrl.pack(fill=tk.X)
        self.se_template = tk.StringVar(value=list(PHISHING_TEMPLATES.keys())[0])
        tk.Label(pt_ctrl, text="Template:", font=("Consolas",9),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT)
        tk.OptionMenu(pt_ctrl, self.se_template,
                      *list(PHISHING_TEMPLATES.keys()),
                      command=lambda v: self._se_generate()).pack(side=tk.LEFT, padx=6)
        self.se_target_name = tk.StringVar(value="Ahmed")
        self.se_company     = tk.StringVar(value="TechCorp")
        tk.Label(pt_ctrl, text="Name:", font=("Consolas",8),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(10,4))
        tk.Entry(pt_ctrl, textvariable=self.se_target_name, font=("Consolas",9),
                 bg=T["BG_ELEVATED"], fg=T["YELLOW"], relief=tk.FLAT, bd=3,
                 width=12).pack(side=tk.LEFT)
        tk.Label(pt_ctrl, text="Company:", font=("Consolas",8),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(8,4))
        tk.Entry(pt_ctrl, textvariable=self.se_company, font=("Consolas",9),
                 bg=T["BG_ELEVATED"], fg=T["YELLOW"], relief=tk.FLAT, bd=3,
                 width=14).pack(side=tk.LEFT)
        tk.Button(pt_ctrl, text="🔄 GENERATE", font=("Consolas",9),
                  bg=T["YELLOW"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=8, pady=4, command=self._se_generate).pack(side=tk.LEFT, padx=8)

        pt_split = tk.Frame(pt_f, bg=T["BG_DEEP"])
        pt_split.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        el = tk.Frame(pt_split, bg=T["BG_DEEP"])
        el.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tk.Label(el, text="EMAIL BODY:", font=("Consolas",8,"bold"),
                 bg=T["BG_DEEP"], fg=T["ORANGE"], anchor="w").pack(fill=tk.X)
        self.se_body_text = tk.Text(el, font=("Consolas",9), bg=T["LOG_BG"],
                                     fg=T["TEXT_MID"], relief=tk.FLAT, padx=8, pady=6,
                                     wrap=tk.WORD, state=tk.DISABLED)
        self.se_body_text.pack(fill=tk.BOTH, expand=True)

        er = tk.Frame(pt_split, bg=T["BG_CARD"], width=260, padx=12, pady=12)
        er.pack(side=tk.RIGHT, fill=tk.Y, padx=(8,0))
        er.pack_propagate(False)
        tk.Label(er, text="RED FLAGS", font=("Consolas",9,"bold"),
                 bg=T["BG_CARD"], fg=T["RED"], anchor="w").pack(fill=tk.X)
        tk.Frame(er, bg=T["RED"], height=1).pack(fill=tk.X, pady=4)
        self.se_flags_frame = tk.Frame(er, bg=T["BG_CARD"])
        self.se_flags_frame.pack(fill=tk.BOTH, expand=True)
        tk.Label(er, text="DEFENSE:\nAlways verify sender!\nNever click unknown links!\nCall IT if unsure!",
                 font=("Segoe UI",8), bg=T["BG_CARD"], fg=T["GREEN"],
                 justify="left", wraplength=220).pack(anchor="w", pady=8)

        # Pretexting Scripts tab
        pr_f = tk.Frame(nb_se, bg=T["BG_DEEP"])
        nb_se.add(pr_f, text=" 🎙 Pretexting Scripts ")
        pr_ctrl = tk.Frame(pr_f, bg=T["BG_CARD"], padx=12, pady=8)
        pr_ctrl.pack(fill=tk.X)
        self.se_pretext = tk.StringVar(value=list(PRETEXTING_SCRIPTS.keys())[0])
        tk.Label(pr_ctrl, text="Script:", font=("Consolas",9),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT)
        tk.OptionMenu(pr_ctrl, self.se_pretext,
                      *list(PRETEXTING_SCRIPTS.keys()),
                      command=lambda v: self._se_load_pretext(v)).pack(side=tk.LEFT, padx=6)
        self._se_pretext_widget = tk.Text(pr_f, font=("Consolas",9), bg=T["LOG_BG"],
                                           fg=T["TEXT_MID"], relief=tk.FLAT, padx=10, pady=8,
                                           wrap=tk.WORD, state=tk.DISABLED)
        self._se_pretext_widget.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)
        self._se_pretext_widget.tag_configure("head",    foreground=T["YELLOW"], font=("Consolas",9,"bold"))
        self._se_pretext_widget.tag_configure("script",  foreground=T["TEXT_MID"])
        self._se_pretext_widget.tag_configure("defense", foreground=T["GREEN"])
        self._se_load_pretext(list(PRETEXTING_SCRIPTS.keys())[0])
        self._se_generate()

    def _se_generate(self):
        t = self.se_template.get()
        r = generate_phishing_report(t,
                self.se_target_name.get(), self.se_company.get())
        self.se_body_text.configure(state=tk.NORMAL)
        self.se_body_text.delete(1.0, tk.END)
        self.se_body_text.insert(tk.END, "Subject: " + r["subject"] + "\n" + "-"*50 + "\n\n")
        self.se_body_text.insert(tk.END, r["body"])
        self.se_body_text.configure(state=tk.DISABLED)
        for w in self.se_flags_frame.winfo_children(): w.destroy()
        for flag in r.get("red_flags", []):
            tk.Label(self.se_flags_frame, text="🚩 " + flag,
                     font=("Segoe UI",8), bg=T["BG_CARD"], fg=T["ORANGE"],
                     anchor="w", wraplength=220, justify="left").pack(fill=tk.X, pady=2)

    def _se_load_pretext(self, name):
        script = PRETEXTING_SCRIPTS.get(name, "")
        self._se_pretext_widget.configure(state=tk.NORMAL)
        self._se_pretext_widget.delete(1.0, tk.END)
        for line in script.split("\n"):
            tag = "head" if any(line.startswith(k) for k in
                                ["SCENARIO","WHY IT","DEFENSE"]) else \
                  "defense" if line.strip().startswith("✓") else "script"
            self._se_pretext_widget.insert(tk.END, line + "\n", tag)
        self._se_pretext_widget.configure(state=tk.DISABLED)

    # ══════════════════════════════════════════════════════════════════════
    # TAB: METASPLOIT LAUNCHER
    # ══════════════════════════════════════════════════════════════════════
    def _tab_msf(self, parent):
        tk.Label(parent, text="  💀  METASPLOIT FRAMEWORK LAUNCHER",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["RED"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Module browser · Command generator · Cheat sheet",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["RED"], height=2).pack(fill=tk.X)
        tk.Label(parent,
                 text="  LEGAL WARNING: Only use on systems you OWN or have WRITTEN PERMISSION!",
                 font=("Consolas",9,"bold"), bg="#1A0000", fg=T["RED"],
                 anchor="w", padx=14, pady=5).pack(fill=tk.X)

        nb_msf = ttk.Notebook(parent); nb_msf.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        # Module browser
        mb_f = tk.Frame(nb_msf, bg=T["BG_DEEP"])
        nb_msf.add(mb_f, text=" 📦 Module Browser ")
        mb_split = tk.Frame(mb_f, bg=T["BG_DEEP"])
        mb_split.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        cat_f = tk.Frame(mb_split, bg=T["BG_CARD"], width=200)
        cat_f.pack(side=tk.LEFT, fill=tk.Y)
        cat_f.pack_propagate(False)
        tk.Label(cat_f, text="CATEGORIES", font=("Consolas",8,"bold"),
                 bg=T["BG_CARD"], fg=T["RED"], anchor="w", padx=6).pack(fill=tk.X, pady=4)
        cat_tree = ttk.Treeview(cat_f, show="tree", selectmode="browse")
        cat_tree.pack(fill=tk.BOTH, expand=True)
        for cat in MSF_MODULES:
            cat_tree.insert("", "end", text=cat, iid=cat, tags=("cat",))
        cat_tree.tag_configure("cat", foreground=T["ORANGE"])

        mod_f = tk.Frame(mb_split, bg=T["BG_DEEP"])
        mod_f.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(8,0))
        tk.Label(mod_f, text="MODULES", font=("Consolas",8,"bold"),
                 bg=T["BG_DEEP"], fg=T["CYAN"], anchor="w").pack(fill=tk.X, pady=(0,4))
        self.msf_mod_tree = ttk.Treeview(mod_f, columns=("Module","Desc"), show="headings")
        self.msf_mod_tree.heading("Module", text="Module Path")
        self.msf_mod_tree.heading("Desc",   text="Description")
        self.msf_mod_tree.column("Module", width=310)
        self.msf_mod_tree.column("Desc",   width=260)
        self.msf_mod_tree.tag_configure("module", foreground=T["TEXT_MID"])
        mvsb = ttk.Scrollbar(mod_f, orient=tk.VERTICAL, command=self.msf_mod_tree.yview)
        self.msf_mod_tree.configure(yscrollcommand=mvsb.set)
        mvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.msf_mod_tree.pack(fill=tk.BOTH, expand=True)

        def _cat_sel(e):
            sel = cat_tree.selection()
            if not sel: return
            for r in self.msf_mod_tree.get_children(): self.msf_mod_tree.delete(r)
            for mod, desc in MSF_MODULES.get(sel[0], {}).items():
                self.msf_mod_tree.insert("","end",values=(mod,desc),tags=("module",))
        cat_tree.bind("<<TreeviewSelect>>", _cat_sel)
        if MSF_MODULES:
            first = list(MSF_MODULES.keys())[0]
            cat_tree.selection_set(first); _cat_sel(None)

        # Command generator
        cg_f = tk.Frame(nb_msf, bg=T["BG_DEEP"])
        nb_msf.add(cg_f, text=" ⚡ Cmd Generator ")
        cg_r = tk.Frame(cg_f, bg=T["BG_CARD"], padx=12, pady=8); cg_r.pack(fill=tk.X)
        self.msf_target = tk.StringVar(value="192.168.1.100")
        self.msf_lhost  = tk.StringVar(value="192.168.1.1")
        self.msf_lport  = tk.StringVar(value="4444")
        for label, var, w in [("RHOSTS:", self.msf_target, 16),
                                ("LHOST:",  self.msf_lhost,  14),
                                ("LPORT:",  self.msf_lport,  8)]:
            tk.Label(cg_r, text=label, font=("Consolas",9),
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(10,4))
            tk.Entry(cg_r, textvariable=var, font=("Consolas",9),
                     bg=T["BG_ELEVATED"], fg=T["RED"], insertbackground=T["RED"],
                     relief=tk.FLAT, bd=3, width=w).pack(side=tk.LEFT)
        all_mods = [m for cat in MSF_MODULES.values() for m in cat.keys()]
        self.msf_sel_module = tk.StringVar(value=all_mods[0] if all_mods else "")
        tk.Label(cg_r, text="Module:", font=("Consolas",9),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(side=tk.LEFT, padx=(10,4))
        tk.Entry(cg_r, textvariable=self.msf_sel_module, font=("Consolas",8),
                 bg=T["BG_ELEVATED"], fg=T["RED"], insertbackground=T["RED"],
                 relief=tk.FLAT, bd=3, width=32).pack(side=tk.LEFT)
        tk.Button(cg_r, text="⚡ GENERATE", font=("Consolas",9,"bold"),
                  bg=T["RED"], fg="white", relief=tk.FLAT, cursor="hand2",
                  padx=10, pady=5, command=self._msf_generate).pack(side=tk.LEFT, padx=8)
        self.msf_cmd_text = tk.Text(cg_f, font=("Consolas",11), bg=T["LOG_BG"],
                                     fg=T["RED"], relief=tk.FLAT, padx=12, pady=10, height=10)
        self.msf_cmd_text.pack(fill=tk.X, padx=8, pady=4)
        tk.Button(cg_f, text="📋 COPY COMMANDS", font=("Consolas",9,"bold"),
                  bg=T["BG_ELEVATED"], fg=T["RED"], relief=tk.FLAT, cursor="hand2",
                  padx=12, pady=6,
                  command=lambda: (self.clipboard_clear(),
                                   self.clipboard_append(self.msf_cmd_text.get(1.0,tk.END)),
                                   self._set_status("Commands copied!"))
                  ).pack(anchor="w", padx=8, pady=4)

        # Cheat Sheet
        cs_f = tk.Frame(nb_msf, bg=T["BG_DEEP"])
        nb_msf.add(cs_f, text=" 📋 Cheat Sheet ")
        cs_nb = ttk.Notebook(cs_f); cs_nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        for cat, cmds in MSF_COMMANDS.items():
            cf2 = tk.Frame(cs_nb, bg=T["BG_DEEP"]); cs_nb.add(cf2, text=" " + cat + " ")
            ct2 = tk.Text(cf2, font=("Consolas",9), bg=T["LOG_BG"], fg=T["TEXT_MID"],
                          relief=tk.FLAT, padx=10, pady=8, state=tk.DISABLED)
            ct2.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
            ct2.tag_configure("cmd",  foreground=T["GREEN"], font=("Consolas",10))
            ct2.tag_configure("desc", foreground=T["TEXT_DIM"])
            ct2.configure(state=tk.NORMAL)
            for cmd, desc in cmds:
                ct2.insert(tk.END, "  " + cmd + "\n", "cmd")
                ct2.insert(tk.END, "    -> " + desc + "\n\n", "desc")
            ct2.configure(state=tk.DISABLED)
        self.after(500, self._msf_check)

    def _msf_generate(self):
        try: port = int(self.msf_lport.get())
        except Exception: port = 4444
        cmd = generate_msf_command(
            self.msf_sel_module.get(),
            self.msf_target.get(),
            self.msf_lhost.get(), port)
        self.msf_cmd_text.delete(1.0, tk.END)
        self.msf_cmd_text.insert(tk.END, "# Run: msfconsole\n\n" + cmd)

    def _msf_check(self):
        r = check_msf_installed()
        if r.get("installed"):
            self._set_status("Metasploit " + r.get("version","?") + " detected!")
        self._msf_generate()

    # ══════════════════════════════════════════════════════════════════════
    # TAB: SYSTEM ANALYTICS DASHBOARD
    # ══════════════════════════════════════════════════════════════════════
    def _tab_analytics(self, parent):
        tk.Label(parent, text="  📊  SYSTEM ANALYTICS DASHBOARD",
                 font=("Consolas",11,"bold"), bg=T["BG_PANEL"], fg=T["CYAN"],
                 anchor="w", pady=8).pack(fill=tk.X)
        tk.Label(parent, text="  Live CPU/RAM/Disk · Security score · Top processes",
                 font=("Segoe UI",8), bg=T["BG_PANEL"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
        tk.Frame(parent, bg=T["CYAN"], height=2).pack(fill=tk.X)

        ctrl = tk.Frame(parent, bg=T["BG_CARD"], padx=12, pady=8); ctrl.pack(fill=tk.X)
        tk.Button(ctrl, text="🔄 REFRESH", font=("Consolas",10,"bold"),
                  bg=T["CYAN"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=14, pady=6, command=self._analytics_refresh).pack(side=tk.LEFT)
        tk.Button(ctrl, text="🛡 SECURITY SCORE", font=("Consolas",9,"bold"),
                  bg=T["GREEN_DIM"], fg=T["BG_DEEP"], relief=tk.FLAT, cursor="hand2",
                  padx=10, pady=6, command=self._analytics_score).pack(side=tk.LEFT, padx=8)
        self.analytics_ts = tk.Label(ctrl, text="", font=("Consolas",8),
                                      bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.analytics_ts.pack(side=tk.LEFT, padx=8)

        body = tk.Frame(parent, bg=T["BG_DEEP"])
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        left = tk.Frame(body, bg=T["BG_DEEP"])
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        cards_row = tk.Frame(left, bg=T["BG_DEEP"]); cards_row.pack(fill=tk.X)
        self.analytics_cards = {}
        for label, unit, key, color in [
            ("CPU",    "%", "cpu_pct",   T["CYAN"]),
            ("RAM",    "%", "ram_pct",   T["ORANGE"]),
            ("DISK",   "%", "disk_pct",  T["YELLOW"]),
            ("UPTIME", "h", "uptime_h",  T["GREEN"]),
        ]:
            card = tk.Frame(cards_row, bg=T["BG_CARD"], padx=16, pady=12)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            tk.Label(card, text=label, font=("Consolas",8,"bold"),
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"], anchor="w").pack(fill=tk.X)
            val_lbl = tk.Label(card, text="--", font=("Consolas",26,"bold"),
                               bg=T["BG_CARD"], fg=color)
            val_lbl.pack()
            tk.Label(card, text=unit, font=("Consolas",10),
                     bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack()
            bar = tk.Canvas(card, bg=T["BG_ELEVATED"], height=6, highlightthickness=0)
            bar.pack(fill=tk.X, pady=4)
            self.analytics_cards[key] = (val_lbl, bar, color)

        net_card = tk.Frame(left, bg=T["BG_CARD"], padx=16, pady=10)
        net_card.pack(fill=tk.X, pady=(8,0))
        tk.Label(net_card, text="NETWORK I/O", font=("Consolas",8,"bold"),
                 bg=T["BG_CARD"], fg=T["TEXT_DIM"]).pack(anchor="w")
        net_row = tk.Frame(net_card, bg=T["BG_CARD"]); net_row.pack(fill=tk.X)
        self.analytics_sent  = tk.Label(net_row, text="UP -- MB",
                                         font=("Consolas",11,"bold"),
                                         bg=T["BG_CARD"], fg=T["GREEN"])
        self.analytics_sent.pack(side=tk.LEFT)
        self.analytics_recv  = tk.Label(net_row, text="DOWN -- MB",
                                         font=("Consolas",11,"bold"),
                                         bg=T["BG_CARD"], fg=T["CYAN"])
        self.analytics_recv.pack(side=tk.LEFT, padx=20)
        self.analytics_procs = tk.Label(net_row, text="-- processes",
                                         font=("Consolas",9),
                                         bg=T["BG_CARD"], fg=T["TEXT_DIM"])
        self.analytics_procs.pack(side=tk.LEFT, padx=20)

        right = tk.Frame(body, bg=T["BG_DEEP"], width=320)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(10,0))
        right.pack_propagate(False)
        self.analytics_score_canvas = tk.Canvas(right, bg=T["BG_CARD"],
                                                  width=280, height=160,
                                                  highlightthickness=0)
        self.analytics_score_canvas.pack(pady=(0,8))
        tk.Label(right, text="TOP CPU PROCESSES", font=("Consolas",8,"bold"),
                 bg=T["BG_DEEP"], fg=T["ORANGE"], anchor="w").pack(fill=tk.X)
        cols = ("Process", "CPU%", "RAM%")
        self.analytics_proc_tree = ttk.Treeview(right, columns=cols,
                                                  show="headings", height=8)
        for col, w in zip(cols, [140, 60, 60]):
            self.analytics_proc_tree.heading(col, text=col)
            self.analytics_proc_tree.column(col, width=w, anchor="w")
        apvsb = ttk.Scrollbar(right, orient=tk.VERTICAL,
                               command=self.analytics_proc_tree.yview)
        self.analytics_proc_tree.configure(yscrollcommand=apvsb.set)
        apvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.analytics_proc_tree.pack(fill=tk.X)
        self.after(725, self._analytics_refresh)

    def _analytics_refresh(self):
        threading.Thread(target=self._analytics_bg, daemon=True).start()

    def _analytics_bg(self):
        data = get_system_analytics()
        self._ui( lambda: self._analytics_show(data))

    def _analytics_show(self, d):
        if "error" in d:
            self.analytics_ts.configure(text=d["error"]); return
        self.analytics_ts.configure(text="Updated: " + d.get("timestamp",""))
        for key, (val_lbl, bar, color) in self.analytics_cards.items():
            val = d.get(key, 0)
            val_lbl.configure(text=str(round(val, 1)))
            bar.delete("all"); bar.update_idletasks()
            bw = bar.winfo_width() or 200
            pct = min(val/100, 1) if key != "uptime_h" else min(val/240, 1)
            bar.create_rectangle(0, 0, int(bw*pct), 6, fill=color, outline="")
        self.analytics_sent.configure(text="UP " + str(d.get("net_sent_mb",0)) + " MB")
        self.analytics_recv.configure(text="DOWN " + str(d.get("net_recv_mb",0)) + " MB")
        self.analytics_procs.configure(text=str(d.get("processes",0)) + " processes")
        for r in self.analytics_proc_tree.get_children():
            self.analytics_proc_tree.delete(r)
        for p in d.get("top_procs", []):
            self.analytics_proc_tree.insert("","end",
                values=(p["name"], p["cpu"], p["ram"]))

    def _analytics_score(self):
        self.analytics_ts.configure(text="Calculating security score...")
        threading.Thread(target=lambda: self._ui(
            lambda: self._analytics_draw_score(calculate_security_score())),
            daemon=True).start()

    def _analytics_draw_score(self, r):
        c = self.analytics_score_canvas; c.delete("all")
        score = r.get("score", 0); color = r.get("color", T["CYAN"])
        grade = r.get("grade","?"); verdict = r.get("verdict","")
        cx = 140; cy = 80; rad = 60
        c.create_oval(cx-rad,cy-rad,cx+rad,cy+rad, outline=T["BG_ELEVATED"], width=10)
        if score > 0:
            extent = -int(score * 3.6)
            c.create_arc(cx-rad,cy-rad,cx+rad,cy+rad,
                         start=90, extent=extent,
                         outline=color, width=10, style="arc")
        c.create_text(cx, cy-8,  text=str(score),  font=("Consolas",28,"bold"), fill=color)
        c.create_text(cx, cy+18, text=grade,        font=("Consolas",14,"bold"), fill=color)
        c.create_text(cx, cy+38, text=verdict,      font=("Consolas",8),         fill=T["TEXT_DIM"])
        for i, issue in enumerate(r.get("issues",[])[:4]):
            ic = T["RED"] if issue.get("severity")=="HIGH" else T["ORANGE"]
            c.create_text(4, 110+i*14,
                          text="• " + issue["text"][:40],
                          font=("Consolas",7), fill=ic, anchor="w")
        self.analytics_ts.configure(
            text="Score: " + str(score) + "/100  Grade: " + grade + "  " + verdict)


    # ══════════════════════════════════════════════════════════════════════
    # TAB: SYSTEM DASHBOARD (dedicated)
    # ══════════════════════════════════════════════════════════════════════
    def _tab_sys_dashboard(self, parent):
        import psutil, platform, datetime as dt
        T2 = T
        # Header
        hdr = tk.Frame(parent, bg=T2["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=T2["CYAN"], height=4).pack(fill=tk.X)
        h_inner = tk.Frame(hdr, bg=T2["BG_PANEL"], padx=16, pady=10)
        h_inner.pack(fill=tk.X)
        tk.Label(h_inner, text="🖥  " + self.L.get("dashboard_sys","SYSTEM DASHBOARD"),
                 font=("Consolas",14,"bold"), bg=T2["BG_PANEL"],
                 fg=T2["CYAN"]).pack(side=tk.LEFT)
        self.sysd_ts = tk.Label(h_inner, text="", font=("Consolas",8),
                                 bg=T2["BG_PANEL"], fg=T2["TEXT_DIM"])
        self.sysd_ts.pack(side=tk.RIGHT)
        tk.Button(h_inner, text="🔄 " + self.L.get("refresh","REFRESH"),
                  font=("Consolas",9,"bold"), bg=T2["CYAN"], fg=T2["BG_DEEP"],
                  relief=tk.FLAT, cursor="hand2", padx=10, pady=4,
                  command=self._sysd_refresh).pack(side=tk.RIGHT, padx=8)

        body = tk.Frame(parent, bg=T2["BG_DEEP"]); body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # ── Row 1: 4 metric cards ─────────────────────────────────────────
        row1 = tk.Frame(body, bg=T2["BG_DEEP"]); row1.pack(fill=tk.X, pady=(0,6))
        self._sysd_cards = {}
        metrics = [
            ("CPU",    "%",  "cpu",    T2["CYAN"]),
            ("RAM",    "%",  "ram",    T2["ORANGE"]),
            ("DISK",   "%",  "disk",   T2["YELLOW"]),
            ("TEMP",   "°C", "temp",   T2["RED"]),
        ]
        for label, unit, key, color in metrics:
            card = tk.Frame(row1, bg=T2["BG_CARD"], padx=12, pady=10)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            tk.Label(card, text=label, font=("Consolas",8,"bold"),
                     bg=T2["BG_CARD"], fg=T2["TEXT_DIM"]).pack(anchor="w")
            val = tk.Label(card, text="--", font=("Consolas",30,"bold"),
                           bg=T2["BG_CARD"], fg=color)
            val.pack()
            tk.Label(card, text=unit, font=("Consolas",9),
                     bg=T2["BG_CARD"], fg=T2["TEXT_DIM"]).pack()
            bar = tk.Canvas(card, bg=T2["BG_ELEVATED"], height=8,
                            highlightthickness=0)
            bar.pack(fill=tk.X, pady=(6,0))
            self._sysd_cards[key] = (val, bar, color)

        # ── Row 2: Processes + Uptime + Info ─────────────────────────────
        row2 = tk.Frame(body, bg=T2["BG_DEEP"]); row2.pack(fill=tk.X, pady=(0,6))

        # System info card
        info_card = tk.Frame(row2, bg=T2["BG_CARD"], padx=12, pady=10)
        info_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0,4))
        tk.Label(info_card, text="SYSTEM INFO", font=("Consolas",9,"bold"),
                 bg=T2["BG_CARD"], fg=T2["CYAN"]).pack(anchor="w")
        tk.Frame(info_card, bg=T2["CYAN"], height=1).pack(fill=tk.X, pady=4)
        self._sysd_info_frame = tk.Frame(info_card, bg=T2["BG_CARD"])
        self._sysd_info_frame.pack(fill=tk.BOTH, expand=True)

        # Network IO card
        net_card = tk.Frame(row2, bg=T2["BG_CARD"], padx=12, pady=10)
        net_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        tk.Label(net_card, text="NETWORK I/O", font=("Consolas",9,"bold"),
                 bg=T2["BG_CARD"], fg=T2["CYAN"]).pack(anchor="w")
        tk.Frame(net_card, bg=T2["CYAN"], height=1).pack(fill=tk.X, pady=4)
        self.sysd_sent  = tk.Label(net_card, text="↑ 0 MB",
                                    font=("Consolas",16,"bold"),
                                    bg=T2["BG_CARD"], fg=T2["GREEN"])
        self.sysd_sent.pack()
        self.sysd_recv  = tk.Label(net_card, text="↓ 0 MB",
                                    font=("Consolas",16,"bold"),
                                    bg=T2["BG_CARD"], fg=T2["CYAN"])
        self.sysd_recv.pack()
        self.sysd_procs = tk.Label(net_card, text="0 processes",
                                    font=("Consolas",10),
                                    bg=T2["BG_CARD"], fg=T2["TEXT_DIM"])
        self.sysd_procs.pack(pady=(8,0))

        # Battery card
        bat_card = tk.Frame(row2, bg=T2["BG_CARD"], padx=12, pady=10)
        bat_card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(4,0))
        tk.Label(bat_card, text="BATTERY & UPTIME", font=("Consolas",9,"bold"),
                 bg=T2["BG_CARD"], fg=T2["CYAN"]).pack(anchor="w")
        tk.Frame(bat_card, bg=T2["CYAN"], height=1).pack(fill=tk.X, pady=4)
        self.sysd_bat_pct = tk.Label(bat_card, text="--",
                                      font=("Consolas",28,"bold"),
                                      bg=T2["BG_CARD"], fg=T2["GREEN"])
        self.sysd_bat_pct.pack()
        tk.Label(bat_card, text="%", font=("Consolas",10),
                 bg=T2["BG_CARD"], fg=T2["TEXT_DIM"]).pack()
        self.sysd_uptime = tk.Label(bat_card, text="Uptime: --",
                                     font=("Consolas",9),
                                     bg=T2["BG_CARD"], fg=T2["TEXT_DIM"])
        self.sysd_uptime.pack(pady=(6,0))

        # ── Row 3: Top processes table ────────────────────────────────────
        row3 = tk.Frame(body, bg=T2["BG_DEEP"]); row3.pack(fill=tk.BOTH, expand=True)
        tk.Label(row3, text="TOP PROCESSES", font=("Consolas",9,"bold"),
                 bg=T2["BG_DEEP"], fg=T2["ORANGE"], anchor="w").pack(fill=tk.X)
        cols = ("PID","Process","CPU %","RAM %","Status")
        self._sysd_proc_tree = ttk.Treeview(row3, columns=cols, show="headings", height=8)
        for col, w in zip(cols, [60,220,80,80,100]):
            self._sysd_proc_tree.heading(col, text=col)
            self._sysd_proc_tree.column(col, width=w, anchor="w")
        self._sysd_proc_tree.tag_configure("high", foreground=T2["RED"])
        self._sysd_proc_tree.tag_configure("norm", foreground=T2["TEXT_MID"])
        pvsb = ttk.Scrollbar(row3, orient=tk.VERTICAL, command=self._sysd_proc_tree.yview)
        self._sysd_proc_tree.configure(yscrollcommand=pvsb.set)
        pvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._sysd_proc_tree.pack(fill=tk.BOTH, expand=True)

        self.after(500, self._sysd_refresh)
        self.after(5000, self._sysd_auto)

    def _sysd_refresh(self):
        import threading as _t
        threading.Thread(target=self._sysd_bg, daemon=True).start()

    def _sysd_auto(self):
        self._sysd_refresh()
        self.after(5000, self._sysd_auto)

    def _sysd_bg(self):
        try:
            import psutil, platform, time as _time, datetime as dt
            cpu  = psutil.cpu_percent(interval=0.5)
            ram  = psutil.virtual_memory()
            disk = psutil.disk_usage("/")
            net  = psutil.net_io_counters()
            pids = len(psutil.pids())
            boot = psutil.boot_time()
            up_s = int(_time.time() - boot)
            up_h = up_s // 3600; up_m = (up_s % 3600) // 60
            up_str = f"{up_h}h {up_m}m"

            # Temperature (may not be available)
            try:
                temps = psutil.sensors_temperatures()
                temp_val = list(temps.values())[0][0].current if temps else 0
            except Exception:
                temp_val = 0

            # Battery
            try:
                bat = psutil.battery()
                bat_pct = int(bat.percent) if bat else None
                bat_stat = "Charging" if bat and bat.power_plugged else "Battery"
            except Exception:
                bat_pct = None; bat_stat = "N/A"

            # Top processes
            procs = []
            for p in sorted(psutil.process_iter(["pid","name","cpu_percent","memory_percent","status"]),
                            key=lambda x: x.info.get("cpu_percent") or 0, reverse=True)[:12]:
                try:
                    procs.append({
                        "pid":    p.info["pid"],
                        "name":   p.info.get("name","?")[:28],
                        "cpu":    round(p.info.get("cpu_percent") or 0, 1),
                        "ram":    round(p.info.get("memory_percent") or 0, 1),
                        "status": p.info.get("status","?")[:10],
                    })
                except Exception:
                    pass

            # OS info
            info = {
                "OS":      platform.system() + " " + platform.release(),
                "Machine": platform.machine(),
                "Hostname":platform.node(),
                "CPU":     platform.processor()[:35] if platform.processor() else "?",
                "Cores":   str(psutil.cpu_count()),
                "RAM":     f"{round(ram.total/1e9,1)} GB",
                "Python":  platform.python_version(),
            }

            data = {
                "cpu":     cpu, "ram":  ram.percent,
                "disk":    disk.percent, "temp": temp_val,
                "sent_mb": round(net.bytes_sent/1e6,1),
                "recv_mb": round(net.bytes_recv/1e6,1),
                "pids":    pids, "uptime": up_str,
                "bat_pct": bat_pct, "bat_stat": bat_stat,
                "procs":   procs, "info": info,
                "ts":      dt.datetime.now().strftime("%H:%M:%S"),
            }
            self._ui(lambda d=data: self._sysd_show(d))
        except Exception as ex:
            self._ui(lambda e=str(ex): self.sysd_ts.configure(text="Error: "+e))

    def _sysd_show(self, d):
        try:
            self.sysd_ts.configure(text="Updated: " + d.get("ts",""))
            for key, (val_lbl, bar, color) in self._sysd_cards.items():
                v = d.get(key, 0)
                val_lbl.configure(text=str(round(v,1)))
                bar.delete("all"); bar.update_idletasks()
                bw = bar.winfo_width() or 300
                pct = min(v/100, 1) if key != "temp" else min(v/100, 1)
                bar.create_rectangle(0, 0, int(bw*pct), 8, fill=color, outline="")

            self.sysd_sent.configure(text="↑ " + str(d.get("sent_mb",0)) + " MB")
            self.sysd_recv.configure(text="↓ " + str(d.get("recv_mb",0)) + " MB")
            self.sysd_procs.configure(text=str(d.get("pids",0)) + " processes")

            # Uptime + battery
            bat = d.get("bat_pct")
            bat_txt = str(bat) + "%" if bat is not None else "AC"
            bat_col = T["RED"] if (bat is not None and bat < 20) else T["GREEN"]
            self.sysd_bat_pct.configure(text=bat_txt, fg=bat_col)
            self.sysd_uptime.configure(text="Uptime: " + d.get("uptime","--"))

            # System info
            for w in self._sysd_info_frame.winfo_children(): w.destroy()
            for k, v in d.get("info",{}).items():
                row = tk.Frame(self._sysd_info_frame, bg=T["BG_CARD"])
                row.pack(fill=tk.X, pady=1)
                tk.Label(row, text=k+":", font=("Consolas",8,"bold"),
                         bg=T["BG_CARD"], fg=T["CYAN"], width=10, anchor="w").pack(side=tk.LEFT)
                tk.Label(row, text=str(v), font=("Consolas",8),
                         bg=T["BG_CARD"], fg=T["TEXT_MID"], anchor="w").pack(side=tk.LEFT)

            # Processes
            for r in self._sysd_proc_tree.get_children():
                self._sysd_proc_tree.delete(r)
            for p in d.get("procs",[]):
                tag = "high" if p["cpu"] > 20 else "norm"
                self._sysd_proc_tree.insert("","end",
                    values=(p["pid"],p["name"],p["cpu"],p["ram"],p["status"]),
                    tags=(tag,))
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════════
    # TAB: NETWORK DASHBOARD (dedicated, with real map)
    # ══════════════════════════════════════════════════════════════════════
    def _tab_net_dashboard(self, parent):
        T2 = T
        # Header
        hdr = tk.Frame(parent, bg=T2["BG_PANEL"]); hdr.pack(fill=tk.X)
        tk.Frame(hdr, bg=T2["GREEN"], height=4).pack(fill=tk.X)
        h_inner = tk.Frame(hdr, bg=T2["BG_PANEL"], padx=16, pady=10)
        h_inner.pack(fill=tk.X)
        tk.Label(h_inner, text="🌐  " + self.L.get("dashboard_net","NETWORK DASHBOARD"),
                 font=("Consolas",14,"bold"), bg=T2["BG_PANEL"],
                 fg=T2["GREEN"]).pack(side=tk.LEFT)
        self.netd_ts = tk.Label(h_inner, text="", font=("Consolas",8),
                                 bg=T2["BG_PANEL"], fg=T2["TEXT_DIM"])
        self.netd_ts.pack(side=tk.RIGHT)
        tk.Button(h_inner, text="🔄 " + self.L.get("refresh","REFRESH"),
                  font=("Consolas",9,"bold"), bg=T2["GREEN"], fg=T2["BG_DEEP"],
                  relief=tk.FLAT, cursor="hand2", padx=10, pady=4,
                  command=self._netd_refresh).pack(side=tk.RIGHT, padx=8)

        body = tk.Frame(parent, bg=T2["BG_DEEP"]); body.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)

        # ── Row 1: Network stats cards ─────────────────────────────────────
        row1 = tk.Frame(body, bg=T2["BG_DEEP"]); row1.pack(fill=tk.X, pady=(0,6))
        self._netd_cards = {}
        for label, key, color in [
            ("CONNECTIONS",  "conns",    T2["CYAN"]),
            ("SENT",         "sent_mb",  T2["GREEN"]),
            ("RECEIVED",     "recv_mb",  T2["ORANGE"]),
            ("SUSPICIOUS",   "sus",      T2["RED"]),
        ]:
            card = tk.Frame(row1, bg=T2["BG_CARD"], padx=12, pady=10)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            tk.Label(card, text=label, font=("Consolas",7,"bold"),
                     bg=T2["BG_CARD"], fg=T2["TEXT_DIM"]).pack(anchor="w")
            val = tk.Label(card, text="--", font=("Consolas",24,"bold"),
                           bg=T2["BG_CARD"], fg=color)
            val.pack()
            self._netd_cards[key] = (val, color)

        # ── Row 2: Split — map + connections ──────────────────────────────
        row2 = tk.Frame(body, bg=T2["BG_DEEP"]); row2.pack(fill=tk.BOTH, expand=True)

        # World map (canvas-based with real coordinates)
        map_frame = tk.Frame(row2, bg=T2["BG_CARD"], padx=4, pady=4)
        map_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        map_header = tk.Frame(map_frame, bg=T2["BG_CARD"]); map_header.pack(fill=tk.X)
        tk.Label(map_header, text="🗺 NETWORK THREAT MAP",
                 font=("Consolas",9,"bold"), bg=T2["BG_CARD"],
                 fg=T2["GREEN"]).pack(side=tk.LEFT)
        # Zoom controls
        zoom_frame = tk.Frame(map_header, bg=T2["BG_CARD"]); zoom_frame.pack(side=tk.RIGHT)
        tk.Button(zoom_frame, text="🔍+", font=("Consolas",9), bg=T2["BG_ELEVATED"],
                  fg=T2["CYAN"], relief=tk.FLAT, cursor="hand2", padx=6,
                  command=lambda: self._netd_zoom(1.2)).pack(side=tk.LEFT, padx=2)
        tk.Button(zoom_frame, text="🔍−", font=("Consolas",9), bg=T2["BG_ELEVATED"],
                  fg=T2["CYAN"], relief=tk.FLAT, cursor="hand2", padx=6,
                  command=lambda: self._netd_zoom(0.8)).pack(side=tk.LEFT, padx=2)
        tk.Button(zoom_frame, text="↺ RESET", font=("Consolas",7), bg=T2["BG_ELEVATED"],
                  fg=T2["TEXT_DIM"], relief=tk.FLAT, cursor="hand2", padx=6,
                  command=self._netd_map_reset).pack(side=tk.LEFT, padx=2)

        self._netd_map = tk.Canvas(map_frame, bg="#0A1628",
                                    highlightthickness=1,
                                    highlightbackground=T2["GREEN"])
        self._netd_map.pack(fill=tk.BOTH, expand=True)
        self._netd_map_zoom   = 1.0
        self._netd_map_offset = [0, 0]
        self._netd_drag_start = [0, 0]

        # Map drag
        def _drag_start(e):
            self._netd_drag_start = [e.x, e.y]
        def _drag_move(e):
            dx = e.x - self._netd_drag_start[0]
            dy = e.y - self._netd_drag_start[1]
            self._netd_map_offset[0] += dx
            self._netd_map_offset[1] += dy
            self._netd_drag_start = [e.x, e.y]
            self._netd_draw_map()
        self._netd_map.bind("<Button-1>",  _drag_start)
        self._netd_map.bind("<B1-Motion>", _drag_move)

        # Right: connections list
        right = tk.Frame(row2, bg=T2["BG_DEEP"], width=340)
        right.pack(side=tk.RIGHT, fill=tk.Y, padx=(8,0))
        right.pack_propagate(False)
        tk.Label(right, text="LIVE CONNECTIONS", font=("Consolas",9,"bold"),
                 bg=T2["BG_DEEP"], fg=T2["ORANGE"], anchor="w").pack(fill=tk.X, pady=(0,4))
        cols = ("Process","Remote","Status","⚠")
        self._netd_conn_tree = ttk.Treeview(right, columns=cols,
                                             show="headings", height=14)
        for col, w in zip(cols, [120,160,80,30]):
            self._netd_conn_tree.heading(col, text=col)
            self._netd_conn_tree.column(col, width=w, anchor="w")
        self._netd_conn_tree.tag_configure("sus",  foreground=T["RED"])
        self._netd_conn_tree.tag_configure("norm", foreground=T["TEXT_MID"])
        nvsb = ttk.Scrollbar(right, orient=tk.VERTICAL,
                              command=self._netd_conn_tree.yview)
        self._netd_conn_tree.configure(yscrollcommand=nvsb.set)
        nvsb.pack(side=tk.RIGHT, fill=tk.Y)
        self._netd_conn_tree.pack(fill=tk.BOTH, expand=True)

        self.after(500, self._netd_refresh)
        self.after(4000, self._netd_auto)

    def _netd_refresh(self):
        import threading as _t
        threading.Thread(target=self._netd_bg, daemon=True).start()

    def _netd_auto(self):
        self._netd_refresh()
        self.after(4000, self._netd_auto)

    def _netd_bg(self):
        try:
            import psutil, datetime as dt
            net     = psutil.net_io_counters()
            conns   = get_live_connections(50)
            sus     = sum(1 for c in conns if c.get("suspicious"))
            data = {
                "conns":   len(conns),
                "sent_mb": round(net.bytes_sent/1e6,1),
                "recv_mb": round(net.bytes_recv/1e6,1),
                "sus":     sus,
                "conn_list": conns,
                "ts": dt.datetime.now().strftime("%H:%M:%S"),
            }
            self._ui(lambda d=data: self._netd_show(d))
        except Exception as ex:
            self._ui(lambda e=str(ex): self.netd_ts.configure(text="Error: "+e))

    def _netd_show(self, d):
        try:
            self.netd_ts.configure(text="Updated: " + d.get("ts",""))
            for key,(val,color) in self._netd_cards.items():
                val.configure(text=str(d.get(key,"--")))

            # Connections
            for r in self._netd_conn_tree.get_children():
                self._netd_conn_tree.delete(r)
            for c in d.get("conn_list",[]):
                if c.get("error"): continue
                tag = "sus" if c.get("suspicious") else "norm"
                self._netd_conn_tree.insert("","end",
                    values=(c.get("process","?")[:18],
                            c.get("remote","?")[:22],
                            c.get("status","?"),
                            "⚠" if c.get("suspicious") else ""),
                    tags=(tag,))

            # Draw map
            self._netd_conn_data = d.get("conn_list",[])
            self._netd_draw_map()
        except Exception:
            pass

    def _netd_draw_map(self):
        """Draw world map with connection dots."""
        try:
            c = self._netd_map; c.delete("all")
            c.update_idletasks()
            W = c.winfo_width() or 500
            H = c.winfo_height() or 300
            ox = self._netd_map_offset[0]
            oy = self._netd_map_offset[1]
            z  = self._netd_map_zoom

            # ── Satellite-style background ─────────────────────────────────
            # Deep ocean gradient (simulated)
            c.create_rectangle(0,0,W,H, fill="#0A1628", outline="")

            # Grid lines (lat/lon)
            grid_col = "#1A2A40"
            for lat in range(-90, 91, 30):
                y = H/2 + (lat/90)*(H/2)*(-1)*z + oy
                c.create_line(0, y, W, y, fill=grid_col, width=1, dash=(2,4))
            for lon in range(-180, 181, 30):
                x = W/2 + (lon/180)*(W/2)*z + ox
                c.create_line(x, 0, x, H, fill=grid_col, width=1, dash=(2,4))

            # ── Continent outlines (simplified polygons) ───────────────────
            def ll_to_xy(lat, lon):
                x = W/2 + (lon/180)*(W/2)*z + ox
                y = H/2 - (lat/90)*(H/2)*z + oy
                return x, y

            continents = {
                "N.America": [(60,-140),(60,-60),(25,-60),(15,-90),(30,-120),(50,-130),(60,-140)],
                "S.America": [(10,-80),(10,-35),(-55,-35),(-55,-75),(10,-80)],
                "Europe":    [(70,30),(70,10),(35,10),(35,40),(55,40),(70,30)],
                "Africa":    [(35,10),(35,50),(-35,50),(-35,15),(10,-20),(35,10)],
                "Asia":      [(70,30),(70,140),(10,140),(10,100),(25,60),(55,60),(70,30)],
                "Australia": [(-15,130),(-15,155),(-40,155),(-40,115),(-15,130)],
            }
            continent_colors = {
                "N.America":"#1B4332","S.America":"#1B4332","Europe":"#2D6A4F",
                "Africa":"#40916C","Asia":"#2D6A4F","Australia":"#1B4332"
            }
            for name, coords in continents.items():
                pts = [coord for lat,lon in coords for coord in ll_to_xy(lat,lon)]
                if len(pts) >= 4:
                    c.create_polygon(pts, fill=continent_colors.get(name,"#1B4332"),
                                     outline="#52B788", width=1)

            # ── Equator line ───────────────────────────────────────────────
            eq_y = H/2 + oy
            c.create_line(0, eq_y, W, eq_y, fill="#2E7D32", width=2, dash=(4,2))

            # ── Known threat locations (APT groups) ───────────────────────
            threat_locs = [
                (55.75, 37.62, "Moscow",    "#FF2D55"),
                (39.92, 116.39,"Beijing",   "#FF6B35"),
                (37.56, 126.98,"Seoul",     "#FFD700"),
                (35.68, 139.69,"Tokyo",     "#00D4FF"),
                (40.71, -74.01,"New York",  "#00FF88"),
                (51.51, -0.13, "London",    "#00D4FF"),
                (48.86, 2.35,  "Paris",     "#7FB3D3"),
                (52.52, 13.40, "Berlin",    "#7FB3D3"),
                (1.35,  103.82,"Singapore", "#FF8C42"),
                (25.20, 55.27, "Dubai",     "#FFD60A"),
                (28.61, 77.21, "Delhi",     "#FF8C42"),
                (24.86, 67.01, "Karachi",   "#00FF88"),  # Home!
            ]
            for lat, lon, city, color in threat_locs:
                x, y = ll_to_xy(lat, lon)
                if -10 <= x <= W+10 and -10 <= y <= H+10:
                    # Pulsing dot
                    r = 6 * z
                    c.create_oval(x-r*2,y-r*2,x+r*2,y+r*2,
                                  outline=color, width=1, fill="")
                    c.create_oval(x-r,y-r,x+r,y+r, fill=color, outline="")
                    if z > 0.7:
                        c.create_text(x+8, y-8, text=city,
                                      font=("Consolas",7), fill=color, anchor="w")

            # ── Your location (Karachi) ────────────────────────────────────
            my_x, my_y = ll_to_xy(24.86, 67.01)
            c.create_oval(my_x-8, my_y-8, my_x+8, my_y+8,
                          outline="#00FF88", width=3, fill="")
            c.create_oval(my_x-3, my_y-3, my_x+3, my_y+3,
                          fill="#00FF88", outline="")
            c.create_text(my_x+10, my_y, text="YOU",
                          font=("Consolas",8,"bold"), fill="#00FF88", anchor="w")

            # ── Connection lines from local to remote IPs ──────────────────
            conn_data = getattr(self, "_netd_conn_data", [])
            for conn in conn_data[:20]:
                if not conn.get("remote") or conn.get("error"): continue
                rem = conn.get("remote","")
                sus = conn.get("suspicious", False)
                line_col = "#FF2D55" if sus else "#00D4FF22"
                # Scatter remote dots randomly (since we don't have geo for all)
                import hashlib as _hl
                h = int(hashlib.md5(rem.encode()).hexdigest()[:8], 16)
                r_lat = ((h % 180) - 90) * 0.8
                r_lon = (((h >> 8) % 360) - 180) * 0.9
                rx, ry = ll_to_xy(r_lat, r_lon)
                c.create_line(my_x, my_y, rx, ry,
                              fill=line_col, width=1, dash=(2,3) if not sus else None)
                if sus:
                    c.create_oval(rx-4,ry-4,rx+4,ry+4, fill="#FF2D55", outline="")

            # Compass
            c.create_text(W-30, 20, text="N", font=("Consolas",10,"bold"), fill="#64B5F6")
            c.create_text(W-30, H-20, text="S", font=("Consolas",10,"bold"), fill="#64B5F6")
            c.create_text(10, H//2, text="W", font=("Consolas",10,"bold"), fill="#64B5F6")
            c.create_text(W-10, H//2, text="E", font=("Consolas",10,"bold"), fill="#64B5F6")

            # Scale bar
            scale_txt = f"Zoom: {round(z,1)}x"
            c.create_text(10, H-15, text=scale_txt, font=("Consolas",8),
                          fill="#64B5F6", anchor="w")
        except Exception:
            pass

    def _netd_zoom(self, factor):
        self._netd_map_zoom = max(0.3, min(5.0, self._netd_map_zoom * factor))
        self._netd_draw_map()

    def _netd_map_reset(self):
        self._netd_map_zoom   = 1.0
        self._netd_map_offset = [0, 0]
        self._netd_draw_map()


# ══════════════════════════════════════════════════════════════════════════
if __name__=="__main__":
    import sys

    # Global error catcher — prevent silent crashes
    def _global_exc(et, ev, tb):
        import traceback, logging
        msg = "".join(traceback.format_exception(et, ev, tb))
        logging.getLogger("CyberShield").error(msg)
        print("[CyberShield Error]", msg[:300])
    sys.excepthook = _global_exc

    # Splash screen
    try:
        from splash import show_splash; show_splash()
    except Exception: pass

    # Registration — auto-activate free trial silently
    try:
        from registration import check_license, activate_license
        lic = check_license()
        if not lic.get("valid"):
            activate_license("FREE-TRIAL", "Shahid", "shahid@cybershield.com")
    except Exception: pass

    # Login
    try:
        from auth import show_login
        ok, user = show_login()
        if not ok: sys.exit(0)
    except Exception: user = "Shahid"

    # Launch app
    App(logged_in_user=user).mainloop()