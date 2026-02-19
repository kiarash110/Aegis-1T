@echo off
:: This ensures the window stays open even if there is a crash
title AEGIS-1T | Pre-Flight Check
mode con: cols=70 lines=25
color 0B

echo ======================================================
echo             🔍 AEGIS-1T SYSTEM DIAGNOSTIC
echo ======================================================
echo.

:: 1. Check if the Python file actually exists
if not exist aegis_check.py (
    color 0C
    echo ❌ ERROR: 'aegis_check.py' not found in this folder!
    pause
    exit
)

:: 2. Run the script
python aegis_check.py

:: 3. Catch errors
if %errorlevel% neq 0 (
    color 0C
    echo.
    echo ❌ ERROR: The Python script crashed. 
    echo Check if you installed 'psutil' (pip install psutil).
)

echo.
echo ======================================================
echo              DIAGNOSTIC PROCESS COMPLETE
echo ======================================================
pause
