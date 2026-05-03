@echo off
title CyberShield Pro
color 0A
cd /d "%~dp0"
echo Starting CyberShield Pro...
python main_app.py
if errorlevel 1 (
    echo.
    echo Error occurred. Installing requirements...
    pip install psutil reportlab
    python main_app.py
)
