@echo off
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0VeriTrust-Receiver-CLI.ps1"
pause
