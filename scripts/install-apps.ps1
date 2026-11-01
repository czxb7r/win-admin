<#
.SYNOPSIS
    Installs a site's standard applications from the vendors' own MSI packages,
    machine-wide and silently. Skips anything already installed.

.DESCRIPTION
    Each application in the built-in catalog below has a vendor download URL,
    the publisher its Authenticode signature must name, and the uninstall-entry
    name that shows it is installed. For every requested application the script:

      1. checks the machine-wide uninstall entries; if present, skips it
      2. downloads the vendor MSI over HTTPS
      3. refuses to install unless the MSI's signature is Valid and its signer
         is the expected publisher
      4. runs msiexec /qn /norestart (verbose MSI log kept in -LogDir)
      5. checks the uninstall entries again

    The applications keep themselves updated afterwards (Google Update, Mozilla
    Maintenance Service), so this is a setup step, not an update tool.

    Runs in a plain elevated SSH session (no SYSTEM scheduled task), so it can
    be used on machines with an EDR agent.

    Last line of output is machine-readable:

        RESULT requested=<n> installed=<n> present=<n> failed=<n> reboot=<True|False>

    Catalog names: chrome, firefox

.PARAMETER Config
    Optional JSON file. Keys used: LogDir, Apps.
    Precedence: command-line argument > config file > built-in default.

.PARAMETER LogDir
    Transcript, MSI logs and downloads. Default C:\tmp.

.PARAMETER Apps
    Catalog names to install. Accepts a list or a comma-separated string.
    Required (argument or config).

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\install-apps.ps1 -Apps chrome,firefox

.EXAMPLE
    win-run -c client.json pc01 install-apps
#>

param(
    [string]$Config = "",
    [string]$LogDir = "C:\tmp",
    [string[]]$Apps = @(),
    [switch]$NoPause
)

# ---- self-elevate to Administrator (forwards all bound arguments) ---------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    $fwd = foreach ($kv in $PSBoundParameters.GetEnumerator()) {
        if ($kv.Value -is [System.Management.Automation.SwitchParameter]) { if ($kv.Value.IsPresent) { "-$($kv.Key)" } }
        else { "-$($kv.Key) `"$(@($kv.Value) -join ',')`"" }
    }
    # -NoExit keeps the elevated window open even on a parse/early error.
    Start-Process -FilePath "powershell.exe" -Verb RunAs `
        -ArgumentList ("-NoExit -ExecutionPolicy Bypass -NoProfile -File `"$PSCommandPath`" " + ($fwd -join ' '))
    exit
}

# ---- config file: CLI argument > config file > default --------------------
if ($Config) {
    if (-not (Test-Path -LiteralPath $Config)) { Write-Host "Config file not found: $Config" -ForegroundColor Red; exit 2 }
    $cfg = Get-Content -Raw -LiteralPath $Config | ConvertFrom-Json
    foreach ($k in 'LogDir', 'Apps') {
        if (-not $PSBoundParameters.ContainsKey($k) -and $null -ne $cfg.$k) { Set-Variable -Name $k -Value $cfg.$k }
    }
}
$isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
if ($env:SSH_CLIENT -or $isSystem) { $NoPause = $true }
$ProgressPreference = 'SilentlyContinue'

# ---- catalog --------------------------------------------------------------
# Url: vendor's stable "latest" MSI link. Signer: required O= of the signing
# certificate. Match: wildcard on the uninstall entry's DisplayName.
$catalog = [ordered]@{
    'chrome'  = @{ Name = 'Google Chrome'
                   Url = 'https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi'
                   Signer = 'Google LLC'; Match = 'Google Chrome' }
    'firefox' = @{ Name = 'Mozilla Firefox'
                   Url = 'https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64&lang=en-US'
                   Signer = 'Mozilla Corporation'; Match = 'Mozilla Firefox*' }
}

$Apps = @($Apps | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
if ($Apps.Count -eq 0) {
    Write-Host ("No applications requested. Pass -Apps (or Apps in -Config). Catalog: {0}" -f ($catalog.Keys -join ', ')) -ForegroundColor Red
    exit 2
}
$unknown = @($Apps | Where-Object { -not $catalog.Contains($_) })
if ($unknown.Count) {
    Write-Host ("Not in the catalog: {0}. Catalog: {1}" -f ($unknown -join ', '), ($catalog.Keys -join ', ')) -ForegroundColor Red
    exit 2
}

# ---- logging --------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$log = Join-Path $LogDir "install-apps_${env:COMPUTERNAME}_${stamp}.log"
Start-Transcript -Path $log -Force | Out-Null
$dlDir = Join-Path $LogDir "install-apps-downloads"
New-Item -ItemType Directory -Path $dlDir -Force | Out-Null

$script:rc = 0
function Finish {
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
    exit $script:rc
}

function Get-Installed($match) {
    $keys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    Get-ItemProperty $keys -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like $match } | Select-Object -First 1
}

Write-Host ""
Write-Host "=== install-apps  ($env:COMPUTERNAME) ===" -ForegroundColor Cyan
Write-Host ""

# Older Windows 10 builds default Windows PowerShell 5.1 to TLS 1.0.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$installed = 0; $present = 0; $failed = 0; $reboot = $false
foreach ($key in $Apps) {
    $app = $catalog[$key]
    Write-Host ("[{0}] {1}" -f $key, $app.Name) -ForegroundColor Cyan

    $have = Get-Installed $app.Match
    if ($have) {
        Write-Host ("  already installed: {0} {1}" -f $have.DisplayName, $have.DisplayVersion)
        $present++
        continue
    }

    try {
        $msi = Join-Path $dlDir "$key.msi"
        Write-Host "  downloading $($app.Url)"
        Invoke-WebRequest -Uri $app.Url -OutFile $msi -UseBasicParsing

        $sig = Get-AuthenticodeSignature -FilePath $msi
        $signer = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '(none)' }
        if ($sig.Status -ne 'Valid' -or $signer -notmatch ('O="?' + [regex]::Escape($app.Signer))) {
            throw ("signature check failed: status {0}, signer {1}; expected {2}" -f $sig.Status, $signer, $app.Signer)
        }
        Write-Host ("  signature Valid: {0}" -f $app.Signer)

        $msiLog = Join-Path $LogDir "install-apps_${key}_${env:COMPUTERNAME}_${stamp}.msi.log"
        Write-Host "  installing (msiexec /qn)..."
        $p = Start-Process -FilePath msiexec.exe -Wait -PassThru `
            -ArgumentList ('/i "{0}" /qn /norestart /l*v "{1}"' -f $msi, $msiLog)
        # 3010 / 1641: installed, reboot required / initiated.
        if ($p.ExitCode -eq 3010 -or $p.ExitCode -eq 1641) { $reboot = $true }
        elseif ($p.ExitCode -ne 0) { throw ("msiexec exit code {0}; log {1}" -f $p.ExitCode, $msiLog) }

        $have = Get-Installed $app.Match
        if (-not $have) { throw "msiexec returned $($p.ExitCode) but no uninstall entry matches '$($app.Match)'" }
        Write-Host ("  installed: {0} {1}" -f $have.DisplayName, $have.DisplayVersion) -ForegroundColor Green
        $installed++
        Remove-Item -LiteralPath $msi -Force -ErrorAction SilentlyContinue
    } catch {
        Write-Host ("  FAILED: {0}" -f $_.Exception.Message) -ForegroundColor Red
        $failed++
    }
}

if ($failed) { $script:rc = 1 }
Write-Host ""
Write-Host ("RESULT requested={0} installed={1} present={2} failed={3} reboot={4}" -f $Apps.Count, $installed, $present, $failed, $reboot)
Finish
