# SMA NetCheck - quick start without manual download.
# Usage (paste into PowerShell):
#   irm https://raw.githubusercontent.com/Nightry/SMA-NetCheck/main/get.ps1 | iex
#
# Downloads the latest release ZIP, extracts it to %LOCALAPPDATA%\SMA-NetCheck
# (overwriting program files, keeping the saved language and reports) and starts the program window.

& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'     # the progress bar makes downloads very slow in PowerShell 5.1
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

    $url  = 'https://github.com/Nightry/SMA-NetCheck/releases/latest/download/SMA-NetCheck.zip'
    $dest = Join-Path $env:LOCALAPPDATA 'SMA-NetCheck'
    $id   = [guid]::NewGuid().ToString('N')
    $zip  = Join-Path $env:TEMP "SMA-NetCheck-$id.zip"
    $tmp  = Join-Path $env:TEMP "SMA-NetCheck-$id"

    try {
        Write-Host 'SMA NetCheck: downloading the latest version...' -ForegroundColor Cyan
        Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
        Expand-Archive -Path $zip -DestinationPath $tmp -Force
        $src = Join-Path $tmp 'SMA-NetCheck'
        if (-not (Test-Path (Join-Path $src 'app\SMA-NetCheck-GUI.ps1'))) { throw 'Unexpected ZIP content.' }

        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Copy-Item -Path (Join-Path $src '*') -Destination $dest -Recurse -Force

        $gui = Join-Path $dest 'app\SMA-NetCheck-GUI.ps1'
        Start-Process -FilePath 'powershell.exe' -ArgumentList "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$gui`""
        Write-Host "SMA NetCheck started. Installed in: $dest" -ForegroundColor Green
        Write-Host 'Next time you can run the same command again (it updates to the latest version).' -ForegroundColor Gray
    } catch {
        Write-Host "SMA NetCheck: download or start failed - $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'Download the ZIP manually: https://github.com/Nightry/SMA-NetCheck/releases/latest' -ForegroundColor Yellow
    } finally {
        foreach ($p in $zip, $tmp) { if (Test-Path $p) { Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue } }
    }
}
