@echo off
rem enable-ssh.cmd -- win-admin USB kit: set up key-based OpenSSH admin access on
rem this machine with enable-ssh-admin.ps1 from this drive. CHANGES the machine
rem (unlike discovery.cmd). Run as administrator. See win-admin README.
rem Uses client.json on this drive when present (AdminUser, AllowFrom, PublicKeys).
setlocal
net session >nul 2>&1
if errorlevel 1 (
    echo This needs administrator rights: right-click enable-ssh.cmd and choose "Run as administrator".
    pause
    exit /b 2
)
set "KIT=%~dp0"
if not exist "%KIT%enable-ssh-admin.ps1" (
    echo Missing enable-ssh-admin.ps1 next to enable-ssh.cmd. Build the drive again with win-usb-kit.
    pause
    exit /b 2
)
set "CFG="
set "DEF="
if exist "%KIT%client.json" (
    set "CFG=%KIT%client.json"
    for /f "usebackq delims=" %%A in (`powershell.exe -NoProfile -Command "try { (@((Get-Content -Raw -LiteralPath (Join-Path $env:KIT 'client.json') | ConvertFrom-Json).AllowFrom) -join ',') } catch { '' }"`) do set "DEF=%%A"
)
echo.
echo Set up OpenSSH admin access on %COMPUTERNAME%.
echo SSH will be allowed only from the address(es) given here: the operator's
echo machine, or the site's subnet router (comma-separated for more than one).
:ask
set "ALLOW="
if defined DEF (
    set /p "ALLOW=Allow SSH from [%DEF%]: "
) else (
    set /p "ALLOW=Allow SSH from: "
)
if not defined ALLOW set "ALLOW=%DEF%"
if not defined ALLOW goto ask
set "LOGS=%KIT%output\ssh"
if defined CFG (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%enable-ssh-admin.ps1" -Config "%CFG%" -AllowFrom "%ALLOW%" -LogDir "%LOGS%" -NoPause
) else (
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%KIT%enable-ssh-admin.ps1" -AllowFrom "%ALLOW%" -LogDir "%LOGS%" -NoPause
)
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" (
    echo Done. The log, with the host key fingerprint, is in %LOGS%
) else (
    echo Finished with errors, see above. Log, if it got that far: %LOGS%
    echo If it says "blocked by your antivirus software": add an antivirus exception
    echo for %KIT%enable-ssh-admin.ps1 ^(that one file^), run this again, and remove
    echo the exception afterwards.
)
pause
exit /b %RC%
