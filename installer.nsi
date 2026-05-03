; ================================================================
;  installer.nsi - Professional Windows Setup (Fixed v3)
;  AI-Powered Vulnerability Assessment System v2.0
;
;  Features:
;   - One-click install
;   - Desktop shortcut auto-created
;   - Start Menu entry
;   - Add/Remove Programs entry
;   - Clean uninstaller
;   - No re-install needed after first install
;
;  HOW TO USE:
;   1. Run build_exe.bat first
;   2. Right-click this file -> "Compile NSIS Script"
;   3. VulnerabilityScanner_Setup_v2.0.exe will be created
; ================================================================

Unicode True
SetCompressor lzma

;---- App Info --------------------------------------------------
!define APP_NAME      "AI Vulnerability Assessment System"
!define APP_VERSION   "2.0"
!define APP_PUBLISHER "FYP - Computer Science"
!define APP_EXE       "VulnerabilityScanner.exe"
!define INSTALL_DIR   "$PROGRAMFILES\VulnerabilityScanner"
!define REG_KEY       "Software\Microsoft\Windows\CurrentVersion\Uninstall\VulnerabilityScanner"

;---- Installer output ------------------------------------------
Name            "${APP_NAME} v${APP_VERSION}"
OutFile         "VulnerabilityScanner_Setup_v2.0.exe"
InstallDir      "${INSTALL_DIR}"
InstallDirRegKey HKLM "${REG_KEY}" "InstallLocation"
RequestExecutionLevel admin
ShowInstDetails show
ShowUninstDetails show

;---- Modern UI -------------------------------------------------
!include "MUI2.nsh"

!define MUI_ABORTWARNING

; Welcome page
!define MUI_WELCOMEPAGE_TITLE    "AI Vulnerability Assessment System v2.0"
!define MUI_WELCOMEPAGE_TEXT     "Welcome! Yeh wizard aapke PC par install karega:$\r$\n$\r$\n\
AI-Powered Intelligent Vulnerability Assessment$\r$\n\
and Threat Prediction System$\r$\n$\r$\n\
Features:$\r$\n\
 - Automatic IP Detection$\r$\n\
 - Network Port Scanner$\r$\n\
 - AI Risk Assessment Engine$\r$\n\
 - Security Awareness Lab$\r$\n\
 - PDF Report Generator$\r$\n$\r$\n\
Continue karne ke liye Next dabayein."

; Finish page - auto launch option
!define MUI_FINISHPAGE_RUN          "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT     "Application abhi launch karein"
!define MUI_FINISHPAGE_TITLE        "Installation Complete!"
!define MUI_FINISHPAGE_TEXT         "AI Vulnerability Assessment System successfully install ho gaya!$\r$\n$\r$\n\
Desktop par shortcut create ho gaya hai.$\r$\n\
Start Menu mein bhi available hai.$\r$\n$\r$\n\
'Launch' checkbox select karke Finish dabayein."

;---- Pages -----------------------------------------------------
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; ================================================================
;  INSTALL SECTION
; ================================================================
Section "MainSection" SEC01

    SectionIn RO    ; Required — cannot be unchecked

    ; Set output directory
    SetOutPath "$INSTDIR"
    SetOverwrite on

    ; ── Copy files ──────────────────────────────────────────────
    DetailPrint "Copying application files..."
    File "dist\VulnerabilityScanner.exe"

    ; Copy README if exists
    IfFileExists "README.txt" 0 +2
        File "README.txt"

    ; ── Desktop Shortcut ────────────────────────────────────────
    DetailPrint "Creating Desktop shortcut..."
    CreateShortCut "$DESKTOP\AI Vulnerability Scanner.lnk" \
        "$INSTDIR\${APP_EXE}" "" \
        "$INSTDIR\${APP_EXE}" 0 \
        SW_SHOWNORMAL \
        "" \
        "AI-Powered Vulnerability Assessment System"

    ; ── Start Menu Shortcuts ────────────────────────────────────
    DetailPrint "Creating Start Menu entries..."
    CreateDirectory "$SMPROGRAMS\${APP_NAME}"

    CreateShortCut "$SMPROGRAMS\${APP_NAME}\AI Vulnerability Scanner.lnk" \
        "$INSTDIR\${APP_EXE}" "" \
        "$INSTDIR\${APP_EXE}" 0 \
        SW_SHOWNORMAL \
        "" \
        "Launch AI Vulnerability Assessment System"

    CreateShortCut "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk" \
        "$INSTDIR\Uninstall.exe"

    IfFileExists "$INSTDIR\README.txt" 0 +3
        CreateShortCut "$SMPROGRAMS\${APP_NAME}\README.lnk" \
            "$INSTDIR\README.txt"

    ; ── Registry — Add/Remove Programs ──────────────────────────
    DetailPrint "Registering in Add/Remove Programs..."
    WriteRegStr   HKLM "${REG_KEY}" "DisplayName"     "${APP_NAME}"
    WriteRegStr   HKLM "${REG_KEY}" "DisplayVersion"  "${APP_VERSION}"
    WriteRegStr   HKLM "${REG_KEY}" "Publisher"       "${APP_PUBLISHER}"
    WriteRegStr   HKLM "${REG_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr   HKLM "${REG_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr   HKLM "${REG_KEY}" "DisplayIcon"     "$INSTDIR\${APP_EXE}"
    WriteRegStr   HKLM "${REG_KEY}" "URLInfoAbout"    "FYP Computer Science"
    WriteRegDWORD HKLM "${REG_KEY}" "NoModify"        1
    WriteRegDWORD HKLM "${REG_KEY}" "NoRepair"        1

    ; Estimate install size (KB)
    WriteRegDWORD HKLM "${REG_KEY}" "EstimatedSize"   51200

    ; ── Write Uninstaller ────────────────────────────────────────
    DetailPrint "Creating uninstaller..."
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    DetailPrint ""
    DetailPrint "Installation complete!"
    DetailPrint "Location: $INSTDIR\${APP_EXE}"
    DetailPrint "Desktop shortcut created."
    DetailPrint "Start Menu entry created."

SectionEnd

; ================================================================
;  UNINSTALL SECTION
; ================================================================
Section "Uninstall"

    ; Remove main EXE and files
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\README.txt"
    Delete "$INSTDIR\Uninstall.exe"

    ; Remove install directory (only if empty after deletes)
    RMDir "$INSTDIR"

    ; Remove Desktop shortcut
    Delete "$DESKTOP\AI Vulnerability Scanner.lnk"

    ; Remove Start Menu folder and shortcuts
    Delete "$SMPROGRAMS\${APP_NAME}\AI Vulnerability Scanner.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"
    Delete "$SMPROGRAMS\${APP_NAME}\README.lnk"
    RMDir  "$SMPROGRAMS\${APP_NAME}"

    ; Remove registry entries
    DeleteRegKey HKLM "${REG_KEY}"

    DetailPrint "Uninstall complete. All files removed."
    MessageBox MB_OK "AI Vulnerability Assessment System has been uninstalled successfully."

SectionEnd
