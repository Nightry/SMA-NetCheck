@echo off
rem SMA NetCheck - dwuklik uruchamia program (okno graficzne). Pliki programu sa w folderze "app".
if not exist "%~dp0app\SMA-NetCheck-GUI.ps1" goto missing
start "" powershell.exe -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0app\SMA-NetCheck-GUI.ps1"
exit /b 0

:missing
echo.
echo  SMA NetCheck
echo.
echo  [PL] Nie znaleziono folderu "app". Rozpakuj CALE archiwum ZIP (prawy przycisk - "Wyodrebnij wszystkie")
echo       i uruchom Start-SMA-NetCheck.cmd z rozpakowanego folderu.
echo  [EN] Folder "app" not found. Extract the WHOLE ZIP archive (right-click - "Extract All")
echo       and run Start-SMA-NetCheck.cmd from the extracted folder.
echo  [DE] Ordner "app" nicht gefunden. Das GANZE ZIP-Archiv entpacken (Rechtsklick - "Alle extrahieren")
echo       und Start-SMA-NetCheck.cmd aus dem entpackten Ordner starten.
echo.
pause
