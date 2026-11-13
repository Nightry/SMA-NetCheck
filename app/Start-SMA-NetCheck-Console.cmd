@echo off
rem SMA NetCheck - uruchomienie bez instalacji (tryb interaktywny)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0SMA-NetCheck.ps1" %*
pause
