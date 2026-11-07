<#
.SYNOPSIS
    Shows, disables or re-enables the User Choice Protection Driver (UCPD).
    Never restarts the machine by itself.

.DESCRIPTION
    UCPD (Windows 10/11) blocks programs other than Windows' own Settings from
    changing the default-app keys for .pdf, .htm, .html, http and https
    (HKCU\...\FileExts\<ext>\UserChoice and ...\UrlAssociations\<proto>\UserChoice).
    It also blocks profile-migration tools from translating those keys, which
    leaves them stuck on the old computer's account and the user unable to
    change their browser or PDF default. See repair-restored-profile.ps1.

    -Disable: driver start type 4 (disabled) and the scheduled task
    \Microsoft\Windows\AppxDeploymentClient\UCPD velocity (which turns the
    driver back on) disabled. Takes effect after a restart.
    -Enable: driver start type 1 (system, the Windows default) and the task
    enabled. Takes effect after a restart.
    Neither: report only.

    UCPD guards only these default-app keys. No other protection is affected.
    Re-enable it as soon as the work that needed it is done.

    Last line of output:
        RESULT present=<True|False> start=<n> task=<state> running=<True|False> reboot=<True|False>
    reboot=True means the running state differs from the configured one.

.PARAMETER Config
    Optional JSON file. Keys used: LogDir.
    Precedence: command-line argument > config file > built-in default.

.PARAMETER Disable
    Turn UCPD off (after a restart).

.PARAMETER Enable
    Turn UCPD back on (after a restart).

.PARAMETER LogDir
    Transcript directory. Default C:\tmp.

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    win-run pc01 set-ucpd -Disable

.EXAMPLE
    win-run pc01 set-ucpd
#>

param(
    [string]$Config = "",
    [switch]$Disable,
    [switch]$Enable,
    [string]$LogDir = "C:\tmp",
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

if ($Disable -and $Enable) { Write-Host "Pass -Disable or -Enable, not both." -ForegroundColor Red; exit 2 }

# ---- logging --------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$log = Join-Path $LogDir "set-ucpd_${env:COMPUTERNAME}_${stamp}.log"
Start-Transcript -Path $log -Force | Out-Null

$script:rc = 0
function Finish {
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
    exit $script:rc
}

$svcKey   = 'HKLM:\SYSTEM\CurrentControlSet\Services\UCPD'
$taskPath = '\Microsoft\Windows\AppxDeploymentClient\'
$taskName = 'UCPD velocity'

function Get-UcpdState {
    $present = Test-Path $svcKey
    $start = $null; $running = $false; $task = 'absent'
    if ($present) {
        $start = (Get-ItemProperty $svcKey).Start
        $running = (sc.exe query UCPD | Out-String) -match 'RUNNING'
    }
    $t = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction SilentlyContinue
    if ($t) { $task = "$($t.State)" }
    return [pscustomobject]@{ Present = $present; Start = $start; Task = $task; Running = $running }
}

try {
    $s = Get-UcpdState
    Write-Host ("Before: present={0} start={1} task={2} running={3}" -f $s.Present, $s.Start, $s.Task, $s.Running)
    if (-not $s.Present) { Write-Host "UCPD is not on this machine; nothing to do." }
    elseif ($Disable) {
        Set-ItemProperty $svcKey -Name Start -Value 4 -Type DWord
        if ($s.Task -ne 'absent') { $null = Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName }
        Write-Host "UCPD disabled; restart to stop the driver."
    }
    elseif ($Enable) {
        Set-ItemProperty $svcKey -Name Start -Value 1 -Type DWord
        if ($s.Task -ne 'absent') { $null = Enable-ScheduledTask -TaskPath $taskPath -TaskName $taskName }
        Write-Host "UCPD enabled; restart to start the driver."
    }
    $s = Get-UcpdState
    Write-Host ("After:  present={0} start={1} task={2} running={3}" -f $s.Present, $s.Start, $s.Task, $s.Running)
    $reboot = $s.Present -and (($s.Start -eq 4 -and $s.Running) -or ($s.Start -ne 4 -and -not $s.Running))
} catch {
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    $script:rc = 1
    $reboot = $false
}

Write-Host ("RESULT present={0} start={1} task={2} running={3} reboot={4}" -f $s.Present, $s.Start, $s.Task, $s.Running, $reboot)
Finish
