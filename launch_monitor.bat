@echo off
title Home Network Guardian - Setup & Launch
color 0A

echo ============================================
echo   Home Network Guardian
echo ============================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH.
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

echo [OK] Python found.
echo.

:: Install dependencies
echo Checking/installing dependencies...
python -m pip install psutil --quiet
if %errorlevel% neq 0 (
    echo [WARNING] Could not install psutil automatically.
    echo Try running:  pip install psutil
)

python -m pip install scapy --quiet
if %errorlevel% neq 0 (
    echo [WARNING] Could not install scapy automatically.
    echo Packet Capture tab will be unavailable.
    echo Try running:  pip install scapy
    echo Also install Npcap from https://npcap.com/ for raw packet access.
)

echo [OK] Dependencies ready.
echo.

:: Check for admin rights (needed for full network visibility)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARNING] Not running as Administrator.
    echo For full network monitoring and packet capture, right-click this
    echo file and choose "Run as administrator".
    echo.
    echo Starting with limited permissions...
    echo.
    timeout /t 3 /nobreak >nul
)

echo Starting Home Network Guardian...
echo.
python "%~dp0home-network-guardian\main.py"

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] The program exited with an error.
    echo Check that the home-network-guardian folder is present alongside this file.
    pause
)
