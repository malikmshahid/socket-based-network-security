"""
process_monitor.py  -  Live Process Monitor
Running processes ki list with CPU/RAM usage and threat detection
Uses psutil (required) + wmic fallback
"""
import subprocess, os, logging, time, threading
from datetime import datetime

logger = logging.getLogger(__name__)

# Processes that are suspicious if running
SUSPICIOUS_PROCESSES = {
    "mimikatz.exe":    ("CRITICAL", "Credential dumping tool"),
    "pwdump.exe":      ("CRITICAL", "Password dumping tool"),
    "procdump.exe":    ("HIGH",     "Process memory dumper"),
    "psexec.exe":      ("HIGH",     "Remote execution tool"),
    "netcat.exe":      ("HIGH",     "Network backdoor tool"),
    "nc.exe":          ("HIGH",     "Netcat — common hacker tool"),
    "nmap.exe":        ("MEDIUM",   "Network scanner"),
    "wireshark.exe":   ("MEDIUM",   "Packet capture tool"),
    "meterpreter.exe": ("CRITICAL", "Metasploit payload"),
    "cobaltstrike.exe":("CRITICAL", "Penetration testing C2"),
    "ncrack.exe":      ("HIGH",     "Network cracker"),
    "john.exe":        ("HIGH",     "Password cracker (John the Ripper)"),
    "hashcat.exe":     ("HIGH",     "GPU password cracker"),
    "cmd.exe":         ("LOW",      "Command prompt — verify if expected"),
    "powershell.exe":  ("MEDIUM",   "PowerShell — verify if expected"),
    "wscript.exe":     ("HIGH",     "Windows Script Host — malware vector"),
    "cscript.exe":     ("HIGH",     "Windows Script Host (console)"),
    "mshta.exe":       ("CRITICAL", "HTML Application host — malware vector"),
    "regsvr32.exe":    ("HIGH",     "DLL registrar — used in fileless malware"),
    "rundll32.exe":    ("MEDIUM",   "DLL runner — verify if expected"),
}

def _run(cmd):
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, creationflags=flags)
        return r.stdout
    except Exception: return ""

def get_processes() -> list:
    """Get list of running processes with details."""
    processes = []

    # Try psutil first
    try:
        import psutil
        for proc in psutil.process_iter(["pid","name","cpu_percent","memory_percent",
                                          "status","username","exe","create_time"]):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                risk_level, risk_desc = SUSPICIOUS_PROCESSES.get(name, ("", ""))
                processes.append({
                    "pid":      info.get("pid", 0),
                    "name":     info.get("name") or "Unknown",
                    "cpu":      round(info.get("cpu_percent") or 0, 1),
                    "ram_pct":  round(info.get("memory_percent") or 0, 1),
                    "status":   info.get("status") or "",
                    "user":     (info.get("username") or "")[:20],
                    "risk":     risk_level,
                    "risk_desc":risk_desc,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(processes, key=lambda p: p.get("cpu", 0), reverse=True)
    except ImportError:
        pass

    # Fallback: tasklist
    out = _run(["tasklist", "/FO", "CSV", "/NH"])
    for line in out.splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 5:
            name = parts[0]
            pid  = parts[1] if len(parts) > 1 else "0"
            mem  = parts[4].replace(",","").replace(" K","").strip() if len(parts) > 4 else "0"
            try: mem_kb = int(mem)
            except: mem_kb = 0
            name_l = name.lower()
            risk_level, risk_desc = SUSPICIOUS_PROCESSES.get(name_l, ("",""))
            processes.append({
                "pid":  pid, "name": name,
                "cpu":  0, "ram_pct": round(mem_kb/1024, 1),
                "status": "running", "user": "",
                "risk": risk_level, "risk_desc": risk_desc,
            })
    return sorted(processes, key=lambda p: p.get("ram_pct", 0), reverse=True)

def kill_process(pid: int) -> tuple:
    try:
        import psutil
        p = psutil.Process(pid)
        p.terminate()
        return True, f"Process {pid} terminated"
    except ImportError:
        ok, msg = True, ""
        try:
            flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            r = subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                               capture_output=True, text=True, creationflags=flags)
            return r.returncode == 0, r.stdout + r.stderr
        except Exception as e:
            return False, str(e)
    except Exception as e:
        return False, str(e)

def get_suspicious_processes(processes: list) -> list:
    return [p for p in processes if p.get("risk") in ("CRITICAL","HIGH","MEDIUM")]
