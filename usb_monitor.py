"""
usb_monitor.py - USB Device Monitor  v8.0
Connected USB devices monitor karta hai, suspicious ones alert karta hai.
Uses WMI (Windows) for real-time detection.
"""
import subprocess, os, threading, time, logging
from datetime import datetime
logger = logging.getLogger(__name__)

SUSPICIOUS_CLASSES = [
    "Rubber Ducky","HID Keyboard","USB Serial","Teensy","DigiSpark",
    "BadUSB","Bash Bunny","O.MG","USB Armory",
]

def _run(cmd, timeout=10):
    try:
        flags = subprocess.CREATE_NO_WINDOW if os.name=="nt" else 0
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=flags)
        return r.stdout
    except Exception as e:
        return str(e)

def get_usb_devices_windows():
    """Get current USB devices via PowerShell/WMIC."""
    out = _run(["wmic","path","Win32_USBHub","get",
                "DeviceID,Description,Manufacturer,Status","/format:list"])
    devices = []; current = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            if current and current.get("Description"):
                devices.append(current)
            current = {}
        elif "=" in line:
            key, _, val = line.partition("=")
            current[key.strip()] = val.strip()
    if current and current.get("Description"):
        devices.append(current)

    # Also check USB controllers
    out2 = _run(["wmic","path","Win32_USBController","get",
                 "Name,Manufacturer,Status","/format:list"])
    for line in out2.splitlines():
        line = line.strip()
        if not line:
            if current and current.get("Name"):
                devices.append({"Description": current.get("Name",""),
                                 "Manufacturer": current.get("Manufacturer",""),
                                 "Status": current.get("Status",""),
                                 "DeviceID": "USB_CTRL"})
            current = {}
        elif "=" in line:
            key, _, val = line.partition("=")
            current[key.strip()] = val.strip()
    return devices

def get_disk_drives():
    """Get USB storage devices."""
    out = _run(["wmic","diskdrive","where","InterfaceType='USB'",
                "get","Caption,SerialNumber,Size,Status","/format:list"])
    drives = []; current = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            if current and current.get("Caption"):
                drives.append(current)
            current = {}
        elif "=" in line:
            k,_,v = line.partition("="); current[k.strip()]=v.strip()
    return drives

def classify_device(dev):
    desc = dev.get("Description","").lower()
    mfr  = dev.get("Manufacturer","").lower()
    risk = "LOW"; color = "#00FF88"; flags = []

    for sus in SUSPICIOUS_CLASSES:
        if sus.lower() in desc or sus.lower() in mfr:
            risk="CRITICAL"; color="#FF2D55"
            flags.append(f"Matches known attack device: {sus}")

    if "hid" in desc and "keyboard" in desc:
        risk="HIGH"; color="#FF8C42"
        flags.append("HID Keyboard — could be BadUSB/Rubber Ducky attack device")
    if "serial" in desc or "uart" in desc:
        flags.append("Serial/UART device — possible programming tool or exploit device")
        if risk=="LOW": risk="MEDIUM"; color="#FFD60A"
    if "storage" in desc or "disk" in desc:
        flags.append("USB Storage — check for unauthorized data exfiltration")
    if not flags:
        flags.append("Standard USB device — no obvious threat")

    dev["risk"]  = risk
    dev["color"] = color
    dev["flags"] = flags
    dev["time"]  = datetime.now().strftime("%H:%M:%S")
    return dev


class USBMonitor:
    def __init__(self, alert_callback=None, interval=5):
        self.callback = alert_callback
        self.interval = interval
        self.running  = False
        self._thread  = None
        self._known   = set()
        self.device_log = []

    def start(self):
        self.running = True
        # Baseline
        current = self._get_current_ids()
        self._known = current
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False

    def _get_current_ids(self):
        devs = get_usb_devices_windows()
        return {d.get("DeviceID","") for d in devs if d.get("DeviceID")}

    def _loop(self):
        while self.running:
            try:
                current = self._get_current_ids()
                new_ids = current - self._known
                if new_ids:
                    all_devs = get_usb_devices_windows()
                    for dev in all_devs:
                        if dev.get("DeviceID","") in new_ids:
                            classified = classify_device(dev)
                            self.device_log.insert(0, classified)
                            if len(self.device_log) > 100:
                                self.device_log = self.device_log[:100]
                            if self.callback:
                                self.callback(classified)
                self._known = current
            except Exception as e:
                logger.error(f"USB monitor: {e}")
            time.sleep(self.interval)

    def get_all_devices(self):
        devs = get_usb_devices_windows()
        drives = get_disk_drives()
        classified_devs = [classify_device(d) for d in devs]
        return classified_devs, drives

    def get_log(self):
        return self.device_log
