<#
.SYNOPSIS
    Health snapshot of a Windows machine as JSON, with a list of findings. Read-only.

.DESCRIPTION
    The point-in-time half of a machine's record (get-inventory is the
    configuration half, kept stable so it can be committed and diffed). This
    one answers "is anything wrong with this machine right now, or has it been
    going wrong for a while?":

      * Hardware errors from the System log (WHEA-Logger): corrected and
        fatal, by component and by month, over the whole retained history.
        Corrected memory errors are the early sign of a failing DIMM.
      * Unexpected shutdowns (Kernel-Power 41), bugchecks (blue screens),
        disk and storage-controller errors, application crashes and hangs, and
        the most frequent errors in the last -Days.
      * Memory and commit use, page file, CPU load, top processes.
      * Physical disks: health, Windows reliability counters, and SMART
        detail through smartctl.exe (smartmontools) when one is found.
      * Volumes and free space, pending reboot, uptime, WMI repository
        consistency, Windows stability index, Defender detections.

    Then it derives "findings" (critical / warning / info) from all of the
    above, so the JSON can be skimmed without reading every section. At the
    machine the findings are also printed.

    smartctl.exe is looked for at -SmartctlPath, then tools\smartctl.exe next
    to this script (a USB kit), then a smartmontools install under Program
    Files. Without it the Windows counters are used; they are often empty on
    SATA drives.

    Output:
      * over SSH (win-run): JSON on stdout only.
      * at the machine: JSON saved to <LogDir>\health_<host>_<timestamp>.json
        (or -OutFile), findings printed.

.PARAMETER Config
    Optional JSON file. Keys used: LogDir, HealthDays, SmartctlPath.

.PARAMETER OutFile
    Also write the JSON to this file.

.PARAMETER LogDir
    Directory for the default output file when run at the machine. Default C:\tmp.

.PARAMETER Days
    Window for crashes, disk errors, error counts and Defender detections.
    Hardware errors and unexpected shutdowns always cover the whole retained
    log. Default 90. Config key: HealthDays.

.PARAMETER SmartctlPath
    Path to smartctl.exe, if not in one of the default places.

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    win-run pc01 get-health > pc01-health.json      (from the operator machine)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\get-health.ps1 -Days 30
#>

param(
    [string]$Config = "",
    [string]$OutFile = "",
    [string]$LogDir = "C:\tmp",
    [int]$Days = 90,
    [string]$SmartctlPath = "",
    [switch]$NoPause
)

$SchemaVersion = 'win-admin/health/v1'

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
    foreach ($k in 'LogDir', 'SmartctlPath') {
        if (-not $PSBoundParameters.ContainsKey($k) -and $null -ne $cfg.$k) { Set-Variable -Name $k -Value $cfg.$k }
    }
    if (-not $PSBoundParameters.ContainsKey('Days') -and $null -ne $cfg.HealthDays) { $Days = [int]$cfg.HealthDays }
}
$isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
$viaSsh = [bool]$env:SSH_CLIENT
if ($viaSsh -or $isSystem) { $NoPause = $true }
if (-not $viaSsh -and -not $OutFile) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    $OutFile = Join-Path $LogDir ("health_{0}_{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

# Stdout must carry nothing but JSON.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

# ---- helpers --------------------------------------------------------------
$script:errors = New-Object System.Collections.Generic.List[string]
function Section([string]$Name, [scriptblock]$Body) {
    try { & $Body } catch { $script:errors.Add("${Name}: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))") }
}
function D($d) { if ($d) { ([datetime]$d).ToString('yyyy-MM-ddTHH:mm:sszzz') } }
function GB($bytes, [int]$digits = 1) { if ($null -ne $bytes) { [math]::Round([double]$bytes / 1GB, $digits) } }
# Explicit $null: a function that outputs nothing serializes as {} inside a hashtable.
function S($v) { if ($null -ne $v) { "$v".Trim() } else { $null } }
function FirstLine($m) { if ($m) { ("$m" -split "`r?`n")[0].Trim() } }
# Get-WinEvent throws when nothing matches; that is an empty result, not an error.
function Get-Events([hashtable]$Filter, [int]$Max = 0) {
    try {
        if ($Max -gt 0) { @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) }
        else { @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop) }
    } catch {
        if ($_.FullyQualifiedErrorId -match 'NoMatchingEventsFound') { @() } else { throw }
    }
}
# Native tools through a wrapper: with ErrorActionPreference Stop, stderr would throw.
function Invoke-Native([string]$Exe) { $ErrorActionPreference = 'Continue'; & $Exe @args 2>&1 | ForEach-Object { "$_" } }

$now = Get-Date
$since = $now.AddDays(-$Days)
$findings = New-Object System.Collections.Generic.List[object]
function Add-Finding([string]$Severity, [string]$Code, [string]$Message) {
    $findings.Add([ordered]@{ severity = $Severity; code = $Code; message = $Message })
}

$out = [ordered]@{}
$out.schema = $SchemaVersion
$out.collected = $now.ToString('yyyy-MM-ddTHH:mm:sszzz')
$out.collectedBy = "$env:USERDOMAIN\$env:USERNAME"
$out.host = $env:COMPUTERNAME
$out.windowDays = $Days

# ---- system ---------------------------------------------------------------
$os = $null
Section 'os' { $script:os = Get-CimInstance Win32_OperatingSystem }
$out.system = Section 'system' {
    $wmi = $null
    $v = (Invoke-Native winmgmt.exe /verifyrepository) -join ' '
    if ($v -match 'inconsistent') { $wmi = $false } elseif ($v -match 'consistent') { $wmi = $true }
    $pending = @()
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) { $pending += 'FileRename' }
    [ordered]@{
        lastBoot          = D $os.LastBootUpTime
        uptimeDays        = [math]::Round(($now - $os.LastBootUpTime).TotalDays, 1)
        timeZone          = (Get-TimeZone).Id
        rebootPending     = $pending
        wmiConsistent     = $wmi
    }
}

$out.stability = Section 'stability' {
    $m = @(Get-CimInstance Win32_ReliabilityStabilityMetrics | Sort-Object TimeGenerated -Descending)
    if ($m.Count) {
        $win = @($m | Where-Object { $_.TimeGenerated -ge $since })
        [ordered]@{
            latest       = [math]::Round($m[0].SystemStabilityIndex, 2)
            latestTime   = D $m[0].TimeGenerated
            windowLowest = $(if ($win.Count) { [math]::Round(($win | Measure-Object SystemStabilityIndex -Minimum).Minimum, 2) })
        }
    }
}

# ---- memory, CPU, processes -----------------------------------------------
$out.memory = Section 'memory' {
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $freeGB = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    $commitLimitGB = [math]::Round($os.TotalVirtualMemorySize / 1MB, 1)
    $commitFreeGB = [math]::Round($os.FreeVirtualMemory / 1MB, 1)
    $pf = @(Get-CimInstance Win32_PageFileUsage | ForEach-Object {
        [ordered]@{ path = S $_.Name; allocatedMB = $_.AllocatedBaseSize; currentMB = $_.CurrentUsage; peakMB = $_.PeakUsage }
    })
    [ordered]@{
        totalGB        = $totalGB
        usedGB         = [math]::Round($totalGB - $freeGB, 1)
        usedPct        = $(if ($totalGB) { [math]::Round(100 * ($totalGB - $freeGB) / $totalGB, 0) })
        commitLimitGB  = $commitLimitGB
        commitUsedGB   = [math]::Round($commitLimitGB - $commitFreeGB, 1)
        commitUsedPct  = $(if ($commitLimitGB) { [math]::Round(100 * ($commitLimitGB - $commitFreeGB) / $commitLimitGB, 0) })
        pageFiles      = $pf
    }
}
$out.cpu = Section 'cpu' {
    [ordered]@{ loadPct = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average, 0) }
}
$out.processes = Section 'processes' {
    $p = @(Get-Process)
    [ordered]@{
        count       = $p.Count
        topByMemory = @($p | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 | ForEach-Object {
            [ordered]@{ name = $_.ProcessName; id = $_.Id; workingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 0) } })
        topByCpu    = @($p | Where-Object { $_.CPU } | Sort-Object CPU -Descending | Select-Object -First 10 | ForEach-Object {
            [ordered]@{ name = $_.ProcessName; id = $_.Id; cpuSeconds = [math]::Round($_.CPU, 0) } })
    }
}

# ---- disks ----------------------------------------------------------------
$out.disks = @(Section 'disks' {
    Get-PhysicalDisk | Sort-Object DeviceId | ForEach-Object {
        $rc = $null
        try { $rc = $_ | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}
        [ordered]@{
            deviceId          = S $_.DeviceId
            model             = S $_.FriendlyName
            serial            = S $_.SerialNumber
            mediaType         = S $_.MediaType
            busType           = S $_.BusType
            sizeGB            = GB $_.Size 0
            health            = S $_.HealthStatus
            operationalStatus = (@($_.OperationalStatus) -join ',')
            reliability       = $(if ($rc) { [ordered]@{
                temperatureC          = $rc.Temperature
                temperatureMaxC       = $rc.TemperatureMax
                wearPct               = $rc.Wear
                powerOnHours          = $rc.PowerOnHours
                readErrorsTotal       = $rc.ReadErrorsTotal
                readErrorsUncorrected = $rc.ReadErrorsUncorrected
                writeErrorsTotal      = $rc.WriteErrorsTotal
                writeErrorsUncorrected = $rc.WriteErrorsUncorrected
            } })
        }
    }
})

# SMART through smartctl, when available. Only the attributes that predict
# failure are kept, plus the NVMe health log.
$smartctl = $null
foreach ($c in @($SmartctlPath, $(if ($PSScriptRoot) { Join-Path $PSScriptRoot 'tools\smartctl.exe' }),
                 "$env:ProgramW6432\smartmontools\bin\smartctl.exe", "${env:ProgramFiles(x86)}\smartmontools\bin\smartctl.exe")) {
    if ($c -and (Test-Path -LiteralPath $c)) { $smartctl = $c; break }
}
$keepAta = @(5, 9, 10, 12, 177, 184, 187, 188, 190, 194, 196, 197, 198, 199, 231, 233, 241)
$out.smart = Section 'smart' {
    if (-not $smartctl) { return [ordered]@{ smartctl = $null; devices = @() } }
    $scanText = (Invoke-Native $smartctl --scan --json) -join "`n"
    $scan = $null
    try { $scan = $scanText | ConvertFrom-Json } catch { throw "smartctl --scan output not JSON (blocked by antivirus?): $($scanText.Substring(0, [math]::Min(200, $scanText.Length)))" }
    $devs = @(foreach ($dev in @($scan.devices)) {
        $a = @('-a', '-j', $dev.name); if ($dev.type) { $a += @('-d', $dev.type) }
        $txt = (Invoke-Native $smartctl @a) -join "`n"
        try {
            $j = $txt | ConvertFrom-Json
            [ordered]@{
                device       = S $dev.name
                model        = S $j.model_name
                serial       = S $j.serial_number
                passed       = $(if ($null -ne $j.smart_status) { [bool]$j.smart_status.passed })
                temperatureC = $j.temperature.current
                powerOnHours = $j.power_on_time.hours
                powerCycles  = $j.power_cycle_count
                ata          = @(@($j.ata_smart_attributes.table) | Where-Object { $_ -and $keepAta -contains [int]$_.id } | ForEach-Object {
                    [ordered]@{ id = $_.id; name = S $_.name; raw = $_.raw.value; value = $_.value; worst = $_.worst; thresh = $_.thresh } })
                nvme         = $j.nvme_smart_health_information_log
            }
        } catch {
            [ordered]@{ device = S $dev.name; error = "unparsed smartctl output" }
        }
    })
    [ordered]@{ smartctl = $smartctl; devices = $devs }
}

$out.volumes = @(Section 'volumes' {
    Get-Volume | Where-Object { $_.DriveLetter -and $_.Size } | Sort-Object DriveLetter | ForEach-Object {
        [ordered]@{
            letter    = "$($_.DriveLetter):"
            label     = S $_.FileSystemLabel
            driveType = S $_.DriveType
            sizeGB    = GB $_.Size 1
            freeGB    = GB $_.SizeRemaining 1
            freePct   = [math]::Round(100 * $_.SizeRemaining / $_.Size, 1)
            health    = S $_.HealthStatus
        }
    }
})

# ---- event history --------------------------------------------------------
$out.eventLogCoverage = Section 'coverage' {
    $o = @{}
    foreach ($log in 'System', 'Application') {
        $e = Get-WinEvent -LogName $log -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
        $o[$log] = $(if ($e) { D $e.TimeCreated })
    }
    [ordered]@{ systemOldest = $o['System']; applicationOldest = $o['Application'] }
}

# WHEA hardware errors: warnings are corrected errors, errors/critical are fatal.
$out.hardwareErrors = Section 'whea' {
    $ev = Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger' }
    $groups = @($ev | ForEach-Object {
        $comp = 'unknown'
        if ($_.Message -match 'Component:\s*([^\r\n]+)') { $comp = $matches[1].Trim() }
        [pscustomobject]@{
            kind = $(if ($_.Level -le 2) { 'fatal' } else { 'corrected' })
            component = $comp; id = $_.Id; time = $_.TimeCreated
        }
    } | Group-Object kind, component, id)
    [ordered]@{
        total  = $ev.Count
        groups = @($groups | ForEach-Object {
            $t = @($_.Group | Sort-Object time)
            $byMonth = [ordered]@{}
            foreach ($x in $t) { $k = $x.time.ToString('yyyy-MM'); if ($byMonth.Contains($k)) { $byMonth[$k]++ } else { $byMonth[$k] = 1 } }
            [ordered]@{
                kind      = $t[0].kind
                component = $t[0].component
                eventId   = $t[0].id
                count     = $t.Count
                first     = D $t[0].time
                last      = D $t[-1].time
                inWindow  = @($t | Where-Object { $_.time -ge $since }).Count
                byMonth   = $byMonth
            }
        })
    }
}

# Unexpected shutdowns: Kernel-Power 41 is logged at the next boot. A non-zero
# bugcheck code means a blue screen; zero means power loss, a hard hang, or a
# held power button.
$out.unexpectedShutdowns = @(Section 'shutdowns' {
    Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41 } | ForEach-Object {
        $bc = $null; try { $bc = '0x{0:X}' -f [uint32]$_.Properties[0].Value } catch {}
        [ordered]@{ time = D $_.TimeCreated; bugcheckCode = $bc }
    }
})

$out.bugchecks = @(Section 'bugchecks' {
    Get-Events @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001 } | ForEach-Object {
        [ordered]@{ time = D $_.TimeCreated; message = FirstLine $_.Message }
    }
})

# Disk and storage-controller errors: bad blocks, controller errors, paging
# errors, retried I/O, NTFS corruption, controller resets. Warnings and errors
# only: NTFS 98 is also logged as information ("volume is healthy").
$out.diskErrors = @(Section 'diskErrors' {
    $want = @{ 'disk' = @(7, 11, 51, 153); 'Ntfs' = @(55, 98); 'Microsoft-Windows-Ntfs' = @(55, 98); 'storahci' = @(129); 'stornvme' = @(11, 129); 'iaStorA' = @(9, 129); 'iaStorAC' = @(9, 129); 'iaStorAVC' = @(9, 129) }
    $ev = Get-Events @{ LogName = 'System'; Id = 7, 9, 11, 51, 55, 98, 129, 153; StartTime = $since }
    @($ev | Where-Object { $_.Level -ge 1 -and $_.Level -le 3 -and $want.ContainsKey($_.ProviderName) -and $want[$_.ProviderName] -contains $_.Id } | Group-Object ProviderName, Id | ForEach-Object {
        $t = @($_.Group | Sort-Object TimeCreated)
        [ordered]@{ provider = $t[0].ProviderName; eventId = $t[0].Id; count = $t.Count; first = D $t[0].TimeCreated; last = D $t[-1].TimeCreated; message = FirstLine $t[-1].Message }
    })
})

$out.appCrashes = @(Section 'appCrashes' {
    $ev = Get-Events @{ LogName = 'Application'; ProviderName = 'Application Error', 'Application Hang'; Id = 1000, 1002; StartTime = $since }
    @($ev | ForEach-Object {
        $app = $null; try { $app = S $_.Properties[0].Value } catch {}
        [pscustomobject]@{ app = $app; kind = $(if ($_.Id -eq 1002) { 'hang' } else { 'crash' }); time = $_.TimeCreated }
    } | Group-Object app, kind | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        $t = @($_.Group | Sort-Object time)
        [ordered]@{ app = $t[0].app; kind = $t[0].kind; count = $t.Count; last = D $t[-1].time }
    })
})

$out.topErrors = @(Section 'topErrors' {
    foreach ($log in 'System', 'Application') {
        $ev = Get-Events @{ LogName = $log; Level = 1, 2; StartTime = $since }
        $ev | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object {
            $t = @($_.Group | Sort-Object TimeCreated)
            [ordered]@{ log = $log; provider = $t[0].ProviderName; eventId = $t[0].Id; count = $t.Count; last = D $t[-1].TimeCreated; message = FirstLine $t[-1].Message }
        }
    }
})

$out.defenderDetections = @(Section 'defender' {
    $names = @{}
    try { Get-MpThreat -ErrorAction Stop | ForEach-Object { $names["$($_.ThreatID)"] = $_.ThreatName } } catch {}
    try { $det = @(Get-MpThreatDetection -ErrorAction Stop) } catch { return }
    $det | Where-Object { $_.InitialDetectionTime -ge $since } | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20 | ForEach-Object {
        [ordered]@{ time = D $_.InitialDetectionTime; threat = $names["$($_.ThreatID)"]; threatId = $_.ThreatID; resource = S (@($_.Resources) | Select-Object -First 1) }
    }
})

# ---- findings -------------------------------------------------------------
Section 'findings' {
    $sys = $out.system
    if ($sys -and $sys.wmiConsistent -eq $false) { Add-Finding 'critical' 'WMI_INCONSISTENT' 'WMI repository is inconsistent; most hardware and OS data may be missing. Run winmgmt /salvagerepository, then collect again.' }
    foreach ($g in @($out.hardwareErrors.groups | Where-Object { $_ })) {
        if ($g.kind -eq 'fatal') {
            Add-Finding 'critical' 'HW_FATAL_ERRORS' "$($g.count) fatal hardware error(s), component $($g.component), last $($g.last)."
        } elseif ($g.component -match 'Memory') {
            $sev = $(if ($g.count -ge 20) { 'critical' } else { 'warning' })
            Add-Finding $sev 'MEMORY_CORRECTED_ERRORS' "$($g.count) corrected memory error(s) from $($g.first) to $($g.last) ($($g.inWindow) in the last $Days days): a DIMM is failing. The firmware may also hold uncorrectable errors (Dell: RMT event log in BIOS setup)."
        } else {
            Add-Finding 'warning' 'HW_CORRECTED_ERRORS' "$($g.count) corrected hardware error(s), component $($g.component), last $($g.last)."
        }
    }
    $sd = @($out.unexpectedShutdowns | Where-Object { $_.time -and [datetime]$_.time -ge $since })
    if ($sd.Count) { Add-Finding $(if ($sd.Count -ge 3) { 'critical' } else { 'warning' }) 'UNEXPECTED_SHUTDOWNS' "$($sd.Count) unexpected shutdown(s) in the last $Days days (Kernel-Power 41), last $($sd[0].time). Power loss, a freeze, or a blue screen." }
    $bc = @($out.bugchecks | Where-Object { $_.time -and [datetime]$_.time -ge $since })
    if ($bc.Count) { Add-Finding 'warning' 'BUGCHECKS' "$($bc.Count) blue screen(s) in the last $Days days, last $($bc[0].time)." }
    foreach ($d in @($out.disks | Where-Object { $_ })) {
        if ($d.health -and $d.health -ne 'Healthy') { Add-Finding 'critical' 'DISK_UNHEALTHY' "Disk $($d.model) ($($d.serial)) reports health '$($d.health)'." }
        $r = $d.reliability
        if ($r -and (([int]$r.readErrorsUncorrected) -gt 0 -or ([int]$r.writeErrorsUncorrected) -gt 0)) { Add-Finding 'warning' 'DISK_UNCORRECTED_IO' "Disk $($d.model): uncorrected read/write errors ($($r.readErrorsUncorrected)/$($r.writeErrorsUncorrected))." }
        if ($r -and $null -ne $r.wearPct -and [int]$r.wearPct -ge 90) { Add-Finding 'warning' 'DISK_WORN' "Disk $($d.model): $($r.wearPct)% of rated wear used." }
    }
    foreach ($s in @($out.smart.devices | Where-Object { $_ })) {
        if ($s.passed -eq $false) { Add-Finding 'critical' 'SMART_FAILED' "SMART overall health FAILED on $($s.model) ($($s.serial)): back up and replace." }
        foreach ($a in @($s.ata | Where-Object { $_ })) {
            if ((5, 187, 196, 197, 198) -contains [int]$a.id -and [long]$a.raw -gt 0) { Add-Finding 'warning' 'SMART_BAD_SECTORS' "$($s.model): SMART $($a.id) $($a.name) = $($a.raw)." }
        }
        $n = $s.nvme
        if ($n) {
            if ([int]$n.critical_warning -ne 0) { Add-Finding 'critical' 'NVME_CRITICAL_WARNING' "$($s.model): NVMe critical warning $($n.critical_warning)." }
            if ([int]$n.percentage_used -ge 90) { Add-Finding 'warning' 'NVME_WORN' "$($s.model): $($n.percentage_used)% of rated endurance used." }
            if ([long]$n.media_errors -gt 0) { Add-Finding 'warning' 'NVME_MEDIA_ERRORS' "$($s.model): $($n.media_errors) media error(s)." }
        }
    }
    foreach ($e in @($out.diskErrors | Where-Object { $_ })) { Add-Finding 'warning' 'DISK_EVENTS' "$($e.count) x $($e.provider) event $($e.eventId) in the last $Days days, last $($e.last): $($e.message)" }
    foreach ($v in @($out.volumes | Where-Object { $_.driveType -eq 'Fixed' })) {
        if ($v.freePct -lt 5 -or $v.freeGB -lt 5) { Add-Finding 'critical' 'LOW_DISK_SPACE' "$($v.letter) has $($v.freeGB) GB free ($($v.freePct)%)." }
        elseif ($v.freePct -lt 15) { Add-Finding 'warning' 'LOW_DISK_SPACE' "$($v.letter) has $($v.freeGB) GB free ($($v.freePct)%)." }
    }
    $m = $out.memory
    if ($m -and $m.commitUsedPct -ge 90) { Add-Finding 'warning' 'MEMORY_COMMIT_HIGH' "Committed memory at $($m.commitUsedPct)% of the limit ($($m.commitUsedGB) of $($m.commitLimitGB) GB): programs can fail to start." }
    elseif ($m -and $m.usedPct -ge 90) { Add-Finding 'info' 'MEMORY_USED_HIGH' "Physical memory $($m.usedPct)% in use at collection ($($m.usedGB) of $($m.totalGB) GB)." }
    $dd = @($out.defenderDetections)
    if ($dd.Count) { Add-Finding 'warning' 'MALWARE_DETECTIONS' "$($dd.Count) Defender detection(s) in the last $Days days, last $($dd[0].time): $($dd[0].threat)." }
    $ac = @($out.appCrashes | Where-Object { $_.count -ge 10 })
    foreach ($a in $ac) { Add-Finding 'info' 'APP_CRASHES' "$($a.app): $($a.count) $($a.kind)(es) in the last $Days days." }
    if ($sys -and $sys.rebootPending.Count) { Add-Finding 'info' 'REBOOT_PENDING' "Reboot pending ($($sys.rebootPending -join ', '))." }
    if ($sys -and $sys.uptimeDays -ge 30) { Add-Finding 'info' 'LONG_UPTIME' "Up $($sys.uptimeDays) days without a restart." }
    if ($out.stability -and $out.stability.latest -lt 5) { Add-Finding 'info' 'LOW_STABILITY' "Windows stability index $($out.stability.latest) of 10." }
    if (-not $smartctl) { Add-Finding 'info' 'NO_SMARTCTL' 'smartctl.exe not found; disk health is from Windows counters only.' }
}
$rank = @{ critical = 0; warning = 1; info = 2 }
$out.findings = @($findings | Sort-Object { $rank[$_.severity] })
$out.errors = @($script:errors)

# ---- output ---------------------------------------------------------------
$json = $out | ConvertTo-Json -Depth 8
if ($OutFile) {
    [IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding $false))
}
if ($viaSsh) {
    try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch {}
    $json
} else {
    Write-Host "Health findings for ${env:COMPUTERNAME}:" -ForegroundColor Cyan
    if (-not $out.findings.Count) { Write-Host "  none" -ForegroundColor Green }
    foreach ($f in $out.findings) {
        $c = @{ critical = 'Red'; warning = 'Yellow'; info = 'Gray' }[$f.severity]
        Write-Host ("  {0,-8} {1}" -f $f.severity.ToUpper(), $f.message) -ForegroundColor $c
    }
    if (-not $OutFile) { $json }
    else {
        Write-Host "Health saved to: $OutFile" -ForegroundColor Green
        if ($script:errors.Count) { Write-Host "$($script:errors.Count) collector error(s); see the 'errors' field." -ForegroundColor Yellow }
    }
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
}
exit 0
