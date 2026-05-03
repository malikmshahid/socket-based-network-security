@echo off
title CyberShield Pro — Build Tool
color 0A
echo.
echo ============================================
echo   CyberShield Pro v11.0 — Build to EXE
echo   SecureNet Solutions
echo ============================================
echo.

echo [1/4] Checking Python...
python --version
if errorlevel 1 (
    echo ERROR: Python not found! Install Python 3.11+
    pause & exit
)

echo [2/4] Installing dependencies...
pip install pyinstaller psutil reportlab pillow pystray --quiet
if errorlevel 1 (
    echo WARNING: Some packages may not have installed
)

echo [3/4] Creating build spec...
python installer_setup.py

echo [4/4] Building EXE...
pyinstaller CyberShield.spec --clean --noconfirm

echo.
echo ============================================
if exist "dist\CyberShield.exe" (
    echo   SUCCESS! EXE created at:
    echo   dist\CyberShield.exe
    echo.
    echo   File size:
    dir dist\CyberShield.exe | find "CyberShield"
) else (
    echo   Build may have issues - check output above
)
echo ============================================
echo.
pause
