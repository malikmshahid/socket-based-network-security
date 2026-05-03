"""
installer_setup.py — CyberShield Pro Installer
Creates desktop shortcut, Start Menu entry, uninstaller
Run as Administrator for full installation
"""

import os, sys, shutil, subprocess, winreg, platform
from pathlib import Path

APP_NAME    = "CyberShield Pro"
APP_VERSION = "11.0"
PUBLISHER   = "SecureNet Solutions"
EXE_NAME    = "CyberShield.exe"
ICON_NAME   = "cybershield.ico"

# Installation directory
INSTALL_DIR = Path(os.environ.get("PROGRAMFILES","C:\\Program Files")) / "CyberShield Pro"
DESKTOP     = Path.home() / "Desktop"
START_MENU  = Path(os.environ.get("APPDATA","")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / APP_NAME


def create_shortcut(target: str, shortcut_path: str, description: str = "", icon: str = ""):
    """Create Windows .lnk shortcut using PowerShell."""
    ps = f"""
$WS = New-Object -ComObject WScript.Shell
$SC = $WS.CreateShortcut('{shortcut_path}')
$SC.TargetPath   = '{target}'
$SC.Description  = '{description}'
$SC.WorkingDirectory = '{os.path.dirname(target)}'
"""
    if icon:
        ps += f"$SC.IconLocation = '{icon}'\n"
    ps += "$SC.Save()"
    subprocess.run(["powershell", "-Command", ps], capture_output=True)


def install():
    print("=" * 60)
    print(f"  {APP_NAME} v{APP_VERSION} — Installer")
    print("=" * 60)
    print(f"  Installing to: {INSTALL_DIR}")
    print()

    src_dir = Path(os.path.dirname(os.path.abspath(__file__)))

    # Create install directory
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[1/6] Created: {INSTALL_DIR}")

    # Copy all Python files
    py_files = list(src_dir.glob("*.py")) + list(src_dir.glob("*.json"))
    for f in py_files:
        shutil.copy2(f, INSTALL_DIR / f.name)
    print(f"[2/6] Copied {len(py_files)} files")

    # Create launcher script
    launcher = INSTALL_DIR / "CyberShield.bat"
    launcher.write_text(
        f'@echo off\ncd /d "{INSTALL_DIR}"\npython main_app.py\npause\n')
    print("[3/6] Created launcher")

    # Desktop shortcut
    lnk = str(DESKTOP / f"{APP_NAME}.lnk")
    create_shortcut(str(launcher), lnk,
                    f"{APP_NAME} — Cybersecurity Suite")
    print(f"[4/6] Desktop shortcut created")

    # Start Menu
    START_MENU.mkdir(parents=True, exist_ok=True)
    sm_lnk = str(START_MENU / f"{APP_NAME}.lnk")
    create_shortcut(str(launcher), sm_lnk, APP_NAME)
    print(f"[5/6] Start Menu entry created")

    # Windows Registry (Add/Remove Programs)
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CyberShieldPro"
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            winreg.SetValueEx(key, "DisplayName",      0, winreg.REG_SZ, APP_NAME)
            winreg.SetValueEx(key, "DisplayVersion",   0, winreg.REG_SZ, APP_VERSION)
            winreg.SetValueEx(key, "Publisher",        0, winreg.REG_SZ, PUBLISHER)
            winreg.SetValueEx(key, "InstallLocation",  0, winreg.REG_SZ, str(INSTALL_DIR))
            winreg.SetValueEx(key, "UninstallString",  0, winreg.REG_SZ,
                              f'python "{INSTALL_DIR / "uninstaller.py"}"')
            winreg.SetValueEx(key, "NoModify",         0, winreg.REG_DWORD, 1)
        print("[6/6] Registry entry created")
    except Exception as e:
        print(f"[6/6] Registry skipped (need Admin): {e}")

    # Create uninstaller
    uninstall_script = INSTALL_DIR / "uninstaller.py"
    uninstall_script.write_text(f'''"""Uninstaller for {APP_NAME}"""
import os, shutil, winreg
from pathlib import Path

print("Uninstalling {APP_NAME}...")
shutil.rmtree(r"{INSTALL_DIR}", ignore_errors=True)
desktop_lnk = Path.home() / "Desktop" / "{APP_NAME}.lnk"
if desktop_lnk.exists(): desktop_lnk.unlink()
try:
    winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\CyberShieldPro")
except: pass
print("Uninstallation complete!")
''')

    print()
    print("=" * 60)
    print(f"  ✅ {APP_NAME} installed successfully!")
    print(f"  Desktop shortcut created")
    print(f"  Run from: Start Menu → {APP_NAME}")
    print("=" * 60)
    input("\nPress Enter to finish...")


def create_pyinstaller_spec():
    """Create PyInstaller spec for building .exe"""
    spec = f'''# -*- mode: python ; coding: utf-8 -*-
# CyberShield Pro — PyInstaller Build Spec

block_cipher = None

a = Analysis(
    ['main_app.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('*.py', '.'),
        ('*.json', '.'),
        ('*.txt', '.'),
    ],
    hiddenimports=[
        'tkinter', 'tkinter.ttk', 'tkinter.messagebox',
        'psutil', 'reportlab', 'reportlab.platypus',
        'hashlib', 'threading', 'socket', 'json',
        'queue', 'secrets', 'platform', 'calendar',
    ],
    hookspath=[],
    hooksconfig={{}},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz, a.scripts, a.binaries, a.zipfiles, a.datas, [],
    name='{EXE_NAME.replace(".exe","")}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,        # No console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon='{ICON_NAME}',  # Uncomment if you have an .ico file
    version='version_info.txt',
)
'''
    with open('CyberShield.spec','w') as f:
        f.write(spec)

    # Version info file
    version_info = '''# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(11,0,0,0), prodvers=(11,0,0,0),
    mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1,
    subtype=0x0, date=(0,0)
  ),
  kids=[
    StringFileInfo([StringTable('040904B0',[
      StringStruct('CompanyName', 'SecureNet Solutions'),
      StringStruct('FileDescription', 'CyberShield Pro'),
      StringStruct('FileVersion', '11.0.0.0'),
      StringStruct('InternalName', 'CyberShield'),
      StringStruct('LegalCopyright', 'Copyright 2026 SecureNet Solutions'),
      StringStruct('OriginalFilename', 'CyberShield.exe'),
      StringStruct('ProductName', 'CyberShield Pro'),
      StringStruct('ProductVersion', '11.0.0.0'),
    ])]),
    VarFileInfo([VarStruct('Translation', [0x409, 1200])])
  ]
)'''
    with open('version_info.txt','w') as f:
        f.write(version_info)
    print("PyInstaller spec created: CyberShield.spec")
    print("Build command: pyinstaller CyberShield.spec")


if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════╗
║   CyberShield Pro v{APP_VERSION} — Setup              ║
║   SecureNet Solutions                        ║
╚══════════════════════════════════════════════╝

Options:
  1. Install (copy files + shortcuts)
  2. Create .exe build spec (PyInstaller)
  3. Exit
""")
    choice = input("Select [1/2/3]: ").strip()
    if choice == "1":
        install()
    elif choice == "2":
        create_pyinstaller_spec()
    else:
        print("Exiting...")
