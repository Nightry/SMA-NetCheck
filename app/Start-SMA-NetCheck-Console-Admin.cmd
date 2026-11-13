@echo off
rem SMA NetCheck - uruchomienie jako administrator (pozwala dodac tymczasowa regule zapory dla testu multicast)
powershell.exe -NoProfile -Command "Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File \"%~dp0SMA-NetCheck.ps1\"'"
