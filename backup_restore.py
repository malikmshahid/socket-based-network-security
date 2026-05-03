"""
backup_restore.py  -  Backup & Restore Settings
All FYP config files ko backup/restore karta hai — zip archive mein
"""
import os, json, zipfile, shutil
from datetime import datetime

BACKUP_DIR   = "backups"
CONFIG_FILES = [
    "scan_schedule.json",
    "usb_whitelist.json",
    "passwords.enc",
    "otp_config.json",
    "score_graph_data.json",
    "darkweb_alerts.json",
    "darkweb_keywords.json",
    "app_settings.json",
]

def create_backup(name: str = "") -> str:
    """Create a zip backup of all config files. Returns backup path."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    label     = f"_{name}" if name else ""
    filename  = f"FYP_backup{label}_{timestamp}.zip"
    filepath  = os.path.join(BACKUP_DIR, filename)

    with zipfile.ZipFile(filepath, "w", zipfile.ZIP_DEFLATED) as zf:
        # Config files
        for cfg in CONFIG_FILES:
            if os.path.exists(cfg):
                zf.write(cfg)
        # Manifest
        manifest = {
            "created":      datetime.now().isoformat(),
            "app_version":  "v9.0",
            "files":        [f for f in CONFIG_FILES if os.path.exists(f)],
            "label":        name,
        }
        zf.writestr("backup_manifest.json", json.dumps(manifest, indent=2))

    size_kb = os.path.getsize(filepath) // 1024
    return filepath, size_kb

def list_backups() -> list:
    """List all available backups."""
    if not os.path.exists(BACKUP_DIR): return []
    backups = []
    for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
        if fname.endswith(".zip"):
            fpath = os.path.join(BACKUP_DIR, fname)
            size  = os.path.getsize(fpath) // 1024
            # Read manifest
            try:
                with zipfile.ZipFile(fpath) as zf:
                    if "backup_manifest.json" in zf.namelist():
                        manifest = json.loads(zf.read("backup_manifest.json"))
                        created  = manifest.get("created","")[:19]
                        files    = len(manifest.get("files",[]))
                        label    = manifest.get("label","")
                    else:
                        created = fname; files = "?"; label = ""
            except Exception:
                created = fname; files = "?"; label = ""
            backups.append({
                "filename": fname,
                "path":     fpath,
                "size_kb":  size,
                "created":  created,
                "files":    files,
                "label":    label,
            })
    return backups

def restore_backup(backup_path: str) -> tuple:
    """Restore config files from backup zip. Returns (success, message)."""
    if not os.path.exists(backup_path):
        return False, f"Backup file not found: {backup_path}"
    try:
        # Backup current state first
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs(BACKUP_DIR, exist_ok=True)
        pre = os.path.join(BACKUP_DIR, f"pre_restore_{ts}.zip")
        with zipfile.ZipFile(pre, "w") as zf:
            for cfg in CONFIG_FILES:
                if os.path.exists(cfg): zf.write(cfg)

        # Restore
        restored = []
        with zipfile.ZipFile(backup_path, "r") as zf:
            for name in zf.namelist():
                if name in CONFIG_FILES:
                    zf.extract(name, ".")
                    restored.append(name)

        return True, f"Restored {len(restored)} file(s):\n" + "\n".join(restored)
    except Exception as e:
        return False, f"Restore failed: {e}"

def delete_backup(backup_path: str) -> bool:
    try: os.remove(backup_path); return True
    except Exception: return False

def get_backup_stats() -> dict:
    backups = list_backups()
    total_size = sum(b["size_kb"] for b in backups)
    return {
        "count":      len(backups),
        "total_kb":   total_size,
        "latest":     backups[0]["created"] if backups else "None",
        "backup_dir": os.path.abspath(BACKUP_DIR),
    }

def save_app_settings(settings: dict):
    with open("app_settings.json","w") as f:
        json.dump(settings, f, indent=2)

def load_app_settings() -> dict:
    defaults = {
        "theme":      "dark",
        "language":   "en",
        "font_size":  10,
        "tab_icons":  True,
        "auto_scan":  False,
        "scan_interval": "daily",
    }
    if not os.path.exists("app_settings.json"): return defaults
    try:
        with open("app_settings.json") as f:
            saved = json.load(f)
            defaults.update(saved)
            return defaults
    except Exception:
        return defaults
