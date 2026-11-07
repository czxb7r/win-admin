@echo off
rem discovery.cmd -- win-admin USB kit: collect a machine's inventory, health and
rem app usage onto this drive. Read-only on the machine; nothing is left on it.
rem Run as administrator (right-click, Run as administrator). See win-admin README.
setlocal
net session >nul 2>&1
if errorlevel 1 (
    echo This needs administrator rights: right-click discovery.cmd and choose "Run as administrator".
    pause
    exit /b 2
)
set "KIT=%~dp0"
for %%S in (get-inventory get-health get-app-usage) do (
    if not exist "%KIT%%%S.ps1" (
        echo Missing %%S.ps1 next to discovery.cmd. Copy the kit again, see the win-admin README.
        pause
        exit /b 2
    )
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& { $kit = $env:KIT; $out = Join-Path $kit ('output\' + $env:COMPUTERNAME + '_' + (Get-Date -Format 'yyyyMMdd-HHmmss')); New-Item -ItemType Directory -Path $out -Force | Out-Null; $rc = 0; foreach ($s in 'get-inventory', 'get-health', 'get-app-usage') { Write-Host ''; Write-Host ('=== ' + $s + ' ===') -ForegroundColor Cyan; $t = Get-Date; & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $kit ($s + '.ps1')) -NoPause -OutFile (Join-Path $out ($s + '.json')); if ($LASTEXITCODE -ne 0) { $rc = 1; Write-Host ($s + ' exited ' + $LASTEXITCODE) -ForegroundColor Red }; Write-Host ('  ' + [int]((Get-Date) - $t).TotalSeconds + ' s') }; Write-Host ''; Write-Host ('Output: ' + $out) -ForegroundColor Green; Get-ChildItem $out | ForEach-Object { Write-Host ('  ' + $_.Name + '  ' + [int]($_.Length / 1KB) + ' KB') }; exit $rc }"
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" (echo Done. Safe to eject the drive and move to the next computer.) else (echo Finished with errors, see above.)
pause
exit /b %RC%
