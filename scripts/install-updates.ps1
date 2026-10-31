<#
.SYNOPSIS
    One Windows Update cycle: search, download, install. Reports whether a reboot
    is needed; never reboots by itself.

.DESCRIPTION
    Uses the Windows Update Agent API (Microsoft.Update.Session), the same engine
    as Settings > Windows Update, against whatever update source the machine is
    configured for (Windows Update, WSUS, or Windows Update for Business policy).

    Installs what Windows would install on its own: every update not marked
    BrowseOnly (security and cumulative updates, drivers and firmware offered
    automatically). Optional updates (previews, optional drivers, feature updates
    offered as optional) are listed only, never installed.

    Run it repeatedly, rebooting in between when it reports reboot=True, until it
    reports pending=0. The last line of output is machine-readable:

        RESULT pending=<n> installed=<n> failed=<n> optional=<n> hidden=<n> reboot=<True|False>

    Over SSH: everything except -ScanOnly must run as SYSTEM, because Windows
    Update refuses downloads, installs and hiding from a network logon
    (E_ACCESSDENIED). Use 'win-run --as-task' with a longer --timeout. On
    machines with an EDR agent, where --as-task is not safe, run -ScanOnly over
    SSH and install at the machine (or from Settings).

    Hiding an update stops Windows offering it (for one that reports Succeeded
    but is offered again every scan). It is reversible with -Unhide.

.PARAMETER Config
    Optional JSON file. Keys used: LogDir.
    Precedence: command-line argument > config file > built-in default.

.PARAMETER LogDir
    Transcript directory. Default C:\tmp.

.PARAMETER ScanOnly
    Search and list; download and install nothing.

.PARAMETER Hide
    Hide the matching pending updates instead of installing (title, wildcards
    allowed, e.g. "Intel Corporation - Extension - 31.0.101.5388" or "*5388*").
    Accepts a list or a comma-separated string.

.PARAMETER Unhide
    Unhide the matching hidden updates (same matching as -Hide).

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\install-updates.ps1

.EXAMPLE
    win-run --as-task --timeout 3600 pc01 install-updates
#>

param(
    [string]$Config = "",
    [string]$LogDir = "C:\tmp",
    [switch]$ScanOnly,
    [string[]]$Hide = @(),
    [string[]]$Unhide = @(),
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
    foreach ($k in 'LogDir') {
        if (-not $PSBoundParameters.ContainsKey($k) -and $null -ne $cfg.$k) { Set-Variable -Name $k -Value $cfg.$k }
    }
}
$isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
if ($env:SSH_CLIENT -or $isSystem) { $NoPause = $true }
$ProgressPreference = 'SilentlyContinue'

# A comma-separated string from a USB/console run or the elevation relaunch.
$Hide   = @($Hide   | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Unhide = @($Unhide | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$installing = -not ($ScanOnly -or $Hide.Count -or $Unhide.Count)

if (-not $ScanOnly -and $env:SSH_CLIENT -and -not $isSystem) {
    Write-Host "Windows Update refuses downloads, installs and hiding from an SSH (network) logon." -ForegroundColor Red
    Write-Host "Run it as SYSTEM with 'win-run --as-task --timeout 3600', or pass -ScanOnly." -ForegroundColor Red
    exit 2
}

# ---- logging --------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$log = Join-Path $LogDir "install-updates_${env:COMPUTERNAME}_${stamp}.log"
Start-Transcript -Path $log -Force | Out-Null

$script:rc = 0
function Finish {
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
    exit $script:rc
}

function Test-RebootPending {
    # Microsoft.Update.SystemInfo is access-denied from a network logon; the
    # registry flags it maintains are readable from any admin session.
    $wu = $false
    try { $wu = (New-Object -ComObject Microsoft.Update.SystemInfo).RebootRequired } catch { }
    $wuKey  = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $cbsKey = Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    return ($wu -or $wuKey -or $cbsKey)
}

function Test-TitleMatch($title, $patterns) {
    foreach ($p in $patterns) { if ($title -like $p) { return $true } }
    return $false
}

function Write-Result($pending, $installed, $failed, $optional, $hidden) {
    Write-Host ("RESULT pending={0} installed={1} failed={2} optional={3} hidden={4} reboot={5}" -f `
        $pending, $installed, $failed, $optional, $hidden, (Test-RebootPending))
}

Write-Host ""
Write-Host "=== install-updates  ($env:COMPUTERNAME) ===" -ForegroundColor Cyan
Write-Host ""

try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'win-admin install-updates'
    $searcher = $session.CreateUpdateSearcher()

    if (Test-RebootPending) { Write-Host "Note: a reboot is already pending from an earlier install." -ForegroundColor Yellow }

    # ---- unhide -----------------------------------------------------------
    if ($Unhide.Count) {
        Write-Host "Searching hidden updates..."
        $n = 0
        foreach ($u in $searcher.Search("IsInstalled=0 and IsHidden=1").Updates) {
            if (Test-TitleMatch $u.Title $Unhide) { $u.IsHidden = $false; $n++; Write-Host ("  unhidden: {0}" -f $u.Title) }
        }
        if ($n -eq 0) { Write-Host "  No hidden update matches." -ForegroundColor Yellow }
    }

    # ---- search -----------------------------------------------------------
    Write-Host "Searching Windows Update..."
    $res = $searcher.Search("IsInstalled=0 and IsHidden=0")
    $hiddenCount = $searcher.Search("IsInstalled=0 and IsHidden=1").Updates.Count

    $auto = @(); $optional = @()
    foreach ($u in $res.Updates) {
        if ($Hide.Count -and (Test-TitleMatch $u.Title $Hide)) {
            $u.IsHidden = $true; $hiddenCount++
            Write-Host ("  hidden:     {0}" -f $u.Title)
            continue
        }
        if ($u.BrowseOnly) { $optional += $u } else { $auto += $u }
    }

    Write-Host ("Pending: {0}   Optional (not installed): {1}   Hidden: {2}" -f $auto.Count, $optional.Count, $hiddenCount)
    foreach ($u in $auto)     { Write-Host ("  [install]  {0}" -f $u.Title) }
    foreach ($u in $optional) { Write-Host ("  [optional] {0}" -f $u.Title) }

    if (-not $installing -or $auto.Count -eq 0) {
        Write-Result $auto.Count 0 0 $optional.Count $hiddenCount
        Finish
    }

    # ---- download ---------------------------------------------------------
    $coll = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($u in $auto) {
        if (-not $u.EulaAccepted) { $u.AcceptEula() }
        [void]$coll.Add($u)
    }
    $codes = @{0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted'}

    Write-Host ""
    Write-Host ("Downloading {0} update(s)..." -f $coll.Count)
    $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll
    $dr = $dl.Download()
    Write-Host ("Download: {0}" -f $codes[[int]$dr.ResultCode])

    # ---- install ----------------------------------------------------------
    Write-Host "Installing..."
    $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll
    $ir = $inst.Install()

    $ok = 0; $bad = 0
    for ($i = 0; $i -lt $coll.Count; $i++) {
        $r = $ir.GetUpdateResult($i)
        if ($r.ResultCode -eq 2 -or $r.ResultCode -eq 3) { $ok++ } else { $bad++ }
        Write-Host ("  {0,-20} 0x{1:X8}  {2}" -f $codes[[int]$r.ResultCode], $r.HResult, $coll.Item($i).Title)
    }
    if ($bad) { $script:rc = 1 }
    Write-Host ""
    Write-Result $auto.Count $ok $bad $optional.Count $hiddenCount
} catch {
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    $script:rc = 1
}
Finish
