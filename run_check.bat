
@echo off
title AEGIS-1T | Pre-Flight Check
mode con: cols=65 lines=25
color 0B

echo ======================================================
echo           🔍 AEGIS-1T SYSTEM DIAGNOSTIC
echo ======================================================
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    color 0C
    echo ❌ ERROR: Python is not installed or not in PATH.
    pause
    exit
)

:: Run the scanner
python aegis_check.py

echo.
echo ======================================================
echo              DIAGNOSTIC PROCESS COMPLETE
echo ======================================================
pause
