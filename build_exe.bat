@echo off
:: ================================================================
::  BUILD_EXE.BAT - FYP EXE Builder (Fixed & Improved)
::  AI-Powered Vulnerability Assessment System v2.0
::  
::  Yeh script sab kuch ek .exe mein bundle karta hai
::  Dobara install karne ki zaroorat nahi!
:: ================================================================

title FYP - Building EXE...
color 0A

echo.
echo  ============================================================
echo   AI Vulnerability Assessment System - EXE Builder
echo   Final Year Project - Computer Science
echo  ============================================================
echo.

:: ── Step 1: Python check ────────────────────────────────────────
echo  [1/5] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [ERROR] Python not found!
    echo  Download: https://www.python.org/downloads/
    echo  Make sure "Add Python to PATH" is checked during install!
    echo.
    pause & exit /b
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo  [OK] %PYVER% found!

:: ── Step 2: Install dependencies ────────────────────────────────
echo.
echo  [2/5] Installing required libraries...
pip install reportlab pyinstaller --quiet --upgrade
if errorlevel 1 (
    echo  [WARNING] Some packages may have failed. Continuing...
)
echo  [OK] Libraries ready!

:: ── Step 3: Clean old builds ────────────────────────────────────
echo.
echo  [3/5] Cleaning previous build files...
if exist "build" rmdir /s /q "build" >nul 2>&1
if exist "dist"  rmdir /s /q "dist"  >nul 2>&1
if exist "*.spec" del /q "*.spec"    >nul 2>&1
echo  [OK] Clean done!

:: ── Step 4: Build EXE ───────────────────────────────────────────
echo.
echo  [4/5] Building EXE (2-4 minutes, please wait)...
echo.

pyinstaller ^
    --onefile ^
    --windowed ^
    --name="VulnerabilityScanner" ^
    --hidden-import=reportlab ^
    --hidden-import=reportlab.lib ^
    --hidden-import=reportlab.lib.pagesizes ^
    --hidden-import=reportlab.lib.styles ^
    --hidden-import=reportlab.lib.units ^
    --hidden-import=reportlab.lib.colors ^
    --hidden-import=reportlab.platypus ^
    --hidden-import=scanner ^
    --hidden-import=risk_engine ^
    --hidden-import=report_gen ^
    --hidden-import=splash ^
    --hidden-import=auth ^
    --hidden-import=network_map ^
    --hidden-import=sys_monitor ^
    --hidden-import=scan_history ^
    --hidden-import=email_report ^
    --hidden-import=psutil ^
    --hidden-import=smtplib ^
    --hidden-import=ssl ^
    --collect-all=reportlab ^
    --clean ^
    --noconfirm ^
    main_app.py

:: ── Step 5: Check result ─────────────────────────────────────────
echo.
if exist "dist\VulnerabilityScanner.exe" (
    echo  [5/5] EXE build successful!
    echo.
    echo  ============================================================
    echo   SUCCESS! Your EXE is ready:
    echo   Location: dist\VulnerabilityScanner.exe
    echo.
    echo   File size:
    for %%A in ("dist\VulnerabilityScanner.exe") do echo   %%~zA bytes  (~%%~zA / 1048576 MB)
    echo.
    echo   NEXT STEP: Run build_installer.bat to create Setup wizard!
    echo  ============================================================
    echo.
    
    :: Copy README to dist folder
    if exist "README.txt" copy "README.txt" "dist\" >nul 2>&1
    
) else (
    echo  [5/5] BUILD FAILED!
    echo.
    echo  Common fixes:
    echo  1. Run this script as Administrator
    echo  2. Temporarily disable antivirus (it may block PyInstaller)
    echo  3. Make sure all .py files are in this folder
    echo  4. Run: pip install pyinstaller --upgrade
    echo.
)

pause
