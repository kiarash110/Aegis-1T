@echo off
title 🛡️ Aegis-1T MFA Setup
echo ==========================================
echo    AEGIS-1T: SECURE MFA CONFIGURATION
echo ==========================================
echo.

# Run the setup script
python setup_mfa.py

echo.
echo [!] Setup Complete. 
echo [!] This file will now self-destruct for security.
echo.
pause

# THE SELF-DESTRUCT COMMAND
# This deletes the file and exits immediately without errors
(goto) 2>nul & del "%~f0"
