@echo off
title AEGIS-1T | NITRO VAULT v1.0.2
mode con: cols=90 lines=35
color 0A

echo 🚀 Initializing AEGIS-1T Environment...

:: Cleanup Python Cache to prevent bloat
echo 🧹 Cleaning temporary cache files...
del /s /q *.pyc >nul 2>&1
for /d /r . %%d in (__pycache__) do @if exist "%%d" rd /s /q "%%d" >nul 2>&1

echo ✅ Environment Clean.
echo.
echo 🛡️  Launching Main Security Suite...
echo ------------------------------------------------------
python aegis_main.py
echo ------------------------------------------------------

echo.
echo [!] Aegis Session Terminated.
pause
