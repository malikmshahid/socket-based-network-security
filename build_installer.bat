@echo off
:: ============================================================
::  BUILD_INSTALLER.BAT
::  Step 2: NSIS se Professional Windows Setup banata hai
::  Pehle build_exe.bat chalao, phir yeh chalao
:: ============================================================

echo.
echo =====================================================
echo   FYP - Installer Builder Script
echo   AI Vulnerability Assessment System
echo =====================================================
echo.

:: Check karo ke .exe bani hai
if not exist "dist\VulnerabilityScanner.exe" (
    echo [ERROR] dist\VulnerabilityScanner.exe nahi mili!
    echo Pehle build_exe.bat chalao!
    pause
    exit /b
)
echo [OK] VulnerabilityScanner.exe found!

:: Check NSIS installed hai
where makensis >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] NSIS install nahi hai!
    echo.
    echo NSIS download karo:
    echo https://nsis.sourceforge.io/Download
    echo.
    echo Install karo phir yeh script dobara chalao.
    pause
    exit /b
)
echo [OK] NSIS found!

:: Installer compile karo
echo.
echo [*] Building installer...
makensis installer.nsi

:: Check successful
if exist "VulnerabilityScanner_Setup_v1.0.exe" (
    echo.
    echo =====================================================
    echo   [SUCCESS] Installer ready!
    echo.
    echo   File: VulnerabilityScanner_Setup_v1.0.exe
    echo.
    echo   Yeh file kisi bhi Windows PC par chalao
    echo   aur software install ho jayega!
    echo =====================================================
) else (
    echo [ERROR] Installer nahi bana. Upar errors dekho.
)

pause
