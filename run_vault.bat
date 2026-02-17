@echo off
:: This version works on ANY computer because it looks for the folder it is currently in
SET parent=%~dp0
cd /d "%parent%"
python aegis_vault.py
pause
