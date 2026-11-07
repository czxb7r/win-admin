<#
.SYNOPSIS
    Reports when each installed application was last run, as JSON. Read-only.

.DESCRIPTION
    Answers "which programs on this machine are still in use, and by whom?"
    before a machine is retired or rebuilt. Windows keeps several records of
    program execution; this script reads three of them and maps them to the
    installed applications:

      * Prefetch (C:\Windows\Prefetch\*.pf): every program run, any user,
        incl. background ones. Run count and up to 8 last run times. Holds the
        most recent ~1024 programs. Empty if the prefetcher is turned off.
      * UserAssist (each user's NTUSER.DAT): programs a person started from
        Start, the taskbar, the desktop or Explorer. Run count and last run per
        user. Shortcut entries are resolved to their target where possible.
      * BAM (Background Activity Moderator, HKLM SYSTEM): last run per user
        and program; Windows drops entries older than about a week.

    Plus the services whose executable lives in an application's folder, so
    an app that only runs in the background (backup agents, remote-access
    tools) is visible as such.

    A user who is signed out has the registry file read from a temporary copy
    (with its transaction logs), loaded under HKU and unloaded again; the
    original is never loaded or changed. Nothing on the machine is changed;
    the temporary copies are deleted.

    Output:
      * over SSH (win-run): JSON on stdout only.
      * at the machine: JSON saved to <LogDir>\app-usage_<host>_<timestamp>.json
        (or -OutFile).

    Interpreting it: times are the machine's local time. Programs that update
    themselves (browsers, Office, Acrobat, OneDrive) show recent prefetch runs
    without anyone using them; userAssist is the "a person started it" signal.
    Activity by the operator while preparing the machine counts too.

.PARAMETER Config
    Optional JSON file. Keys used: LogDir.

.PARAMETER OutFile
    Also write the JSON to this file.

.PARAMETER LogDir
    Directory for the default output file when run at the machine. Default C:\tmp.

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    win-run pc01 get-app-usage > pc01-app-usage.json      (from the operator machine)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\get-app-usage.ps1
#>

param(
    [string]$Config = "",
    [string]$OutFile = "",
    [string]$LogDir = "C:\tmp",
    [switch]$NoPause
)

$SchemaVersion = 'win-admin/app-usage/v1'

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
$viaSsh = [bool]$env:SSH_CLIENT
if ($viaSsh -or $isSystem) { $NoPause = $true }
if (-not $viaSsh -and -not $OutFile) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    $OutFile = Join-Path $LogDir ("app-usage_{0}_{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

# Stdout must carry nothing but JSON.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

# ---- native helpers: prefetch decompression/parsing, DOS device names ----
if (-not ('WaAppUsage' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class WaPrefetch {
    public string ExeName;
    public int Version;
    public int RunCount;
    public long[] RunTimes;
    public string[] Paths;
}

public static class WaAppUsage {
    [DllImport("ntdll.dll")]
    static extern uint RtlGetCompressionWorkSpaceSize(ushort fmt, out uint bufWs, out uint fragWs);
    [DllImport("ntdll.dll")]
    static extern uint RtlDecompressBufferEx(ushort fmt, byte[] ub, int ubSize, byte[] cb, int cbSize, out int final, byte[] ws);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern uint QueryDosDevice(string dev, StringBuilder target, int max);

    public static string DosDevice(string drive) {
        StringBuilder sb = new StringBuilder(1024);
        return QueryDosDevice(drive, sb, sb.Capacity) == 0 ? null : sb.ToString();
    }

    // Windows 8+ prefetch files are "MAM" + XPRESS Huffman compressed.
    static byte[] Decompress(byte[] d) {
        if (d.Length < 8 || d[0] != 0x4D || d[1] != 0x41 || d[2] != 0x4D) return d;
        int size = BitConverter.ToInt32(d, 4);
        int off = ((d[3] & 0x80) != 0) ? 12 : 8;
        uint ws, fws;
        uint st = RtlGetCompressionWorkSpaceSize(4, out ws, out fws);
        if (st != 0) throw new Exception("RtlGetCompressionWorkSpaceSize 0x" + st.ToString("X"));
        byte[] w = new byte[ws], u = new byte[size], c = new byte[d.Length - off];
        Array.Copy(d, off, c, 0, c.Length);
        int fin;
        st = RtlDecompressBufferEx(4, u, size, c, c.Length, out fin, w);
        if (st != 0) throw new Exception("RtlDecompressBufferEx 0x" + st.ToString("X"));
        return u;
    }

    public static WaPrefetch Parse(string path) {
        byte[] b = Decompress(File.ReadAllBytes(path));
        if (b.Length < 0x100 || Encoding.ASCII.GetString(b, 4, 4) != "SCCA") throw new Exception("not a prefetch file");
        WaPrefetch p = new WaPrefetch();
        p.Version = BitConverter.ToInt32(b, 0);
        p.ExeName = Encoding.Unicode.GetString(b, 0x10, 60).Split('\0')[0];
        int metricsOff = BitConverter.ToInt32(b, 0x54);
        int strOff = BitConverter.ToInt32(b, 0x64), strSize = BitConverter.ToInt32(b, 0x68);
        int nTimes, timesOff, rcOff;
        if (p.Version == 17)      { nTimes = 1; timesOff = 0x78; rcOff = 0x90; }
        else if (p.Version == 23) { nTimes = 1; timesOff = 0x80; rcOff = 0x98; }
        else if (p.Version == 26) { nTimes = 8; timesOff = 0x80; rcOff = 0xD0; }
        else                      { nTimes = 8; timesOff = 0x80; rcOff = (metricsOff == 0x128) ? 0xC8 : 0xD0; }
        List<long> times = new List<long>();
        for (int i = 0; i < nTimes; i++) {
            long t = BitConverter.ToInt64(b, timesOff + 8 * i);
            if (t > 0) times.Add(t);
        }
        p.RunTimes = times.ToArray();
        p.RunCount = BitConverter.ToInt32(b, rcOff);
        List<string> paths = new List<string>();
        if (strOff > 0 && strSize > 0 && strOff + strSize <= b.Length) {
            string upper = p.ExeName.ToUpperInvariant();
            foreach (string s in Encoding.Unicode.GetString(b, strOff, strSize).Split('\0')) {
                if (s.Length == 0) continue;
                int slash = s.LastIndexOf('\\');
                string leaf = slash >= 0 ? s.Substring(slash + 1) : s;
                if (upper.Length > 0 && leaf.ToUpperInvariant().StartsWith(upper)) paths.Add(s);
            }
        }
        p.Paths = paths.ToArray();
        return p;
    }
}
'@
}

# ---- helpers --------------------------------------------------------------
$script:errors = New-Object System.Collections.Generic.List[string]
function Section([string]$Name, [scriptblock]$Body) {
    try { & $Body } catch { $script:errors.Add("${Name}: $($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))") }
}
function S($v) { if ($null -ne $v) { "$v".Trim() } }
function ConvertFrom-FileTime([long]$ft) {
    if ($ft -le 0) { return $null }
    try {
        $d = [DateTime]::FromFileTimeUtc($ft)
        if ($d.Year -lt 2000 -or $d.Year -gt 2100) { return $null }
        $d.ToLocalTime().ToString('yyyy-MM-ddTHH:mm:sszzz')
    } catch { $null }
}
function Rot13([string]$s) {
    $sb = New-Object Text.StringBuilder
    foreach ($ch in $s.ToCharArray()) {
        $c = [int]$ch
        if ($c -ge 65 -and $c -le 90) { $c = (($c - 65 + 13) % 26) + 65 }
        elseif ($c -ge 97 -and $c -le 122) { $c = (($c - 97 + 13) % 26) + 97 }
        [void]$sb.Append([char]$c)
    }
    $sb.ToString()
}
# reg.exe through a wrapper: with ErrorActionPreference Stop, its stderr would throw.
function Invoke-Reg { $ErrorActionPreference = 'Continue'; $null = & reg.exe @args 2>&1 }
function Later($a, $b) { if (-not $a) { return $b }; if (-not $b) { return $a }; if ([string]$b -gt [string]$a) { $b } else { $a } }

# Device paths -> drive letters. Prefetch uses \VOLUME{<time>-<serial>}\...
# (serial = volume serial number), BAM uses \Device\HarddiskVolumeN\...
$devMap = @{}; $serialMap = @{}
Section 'volumes' {
    foreach ($d in [IO.DriveInfo]::GetDrives()) {
        $letter = $d.Name.Substring(0, 2)
        $dev = [WaAppUsage]::DosDevice($letter)
        if ($dev) { $script:devMap[$dev.ToLower()] = $letter }
    }
    foreach ($v in @(Get-CimInstance Win32_Volume | Where-Object { $_.DriveLetter -and $null -ne $_.SerialNumber })) {
        $script:serialMap[('{0:X8}' -f [uint32]$v.SerialNumber)] = $v.DriveLetter
    }
}
function Convert-DevicePath([string]$p) {
    if ($p -match '^\\VOLUME\{[0-9A-Fa-f]+-([0-9A-Fa-f]{8})\}(\\.*)$') {
        $l = $serialMap[$matches[1].ToUpper()]; if ($l) { return $l + $matches[2] }
    }
    if ($p -match '^(\\Device\\HarddiskVolume\d+)(\\.*)$') {
        $l = $devMap[$matches[1].ToLower()]; if ($l) { return $l + $matches[2] }
    }
    $p
}

# Executions keyed by lower-case path (or app ID for UserAssist entries that
# are not paths).
$exec = @{}
function Get-Exec([string]$path) {
    $k = $path.ToLower()
    if (-not $exec.ContainsKey($k)) {
        $exec[$k] = [ordered]@{
            path = $path; lastRun = $null
            prefetch = $null; userAssist = @(); bam = @()
        }
    }
    $exec[$k]
}

$out = [ordered]@{}
$out.schema = $SchemaVersion
$out.collected = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
$out.collectedBy = "$env:USERDOMAIN\$env:USERNAME"
$out.host = $env:COMPUTERNAME
$out.timeZone = (Get-TimeZone).Id
$out.lastBoot = Section 'lastBoot' { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-ddTHH:mm:sszzz') }

# ---- profiles -------------------------------------------------------------
$profiles = @(Section 'profiles' {
    Get-CimInstance Win32_UserProfile | Where-Object { -not $_.Special -and $_.LocalPath } | ForEach-Object {
        $name = Split-Path $_.LocalPath -Leaf
        try { $name = (New-Object Security.Principal.SecurityIdentifier($_.SID)).Translate([Security.Principal.NTAccount]).Value } catch {}
        [ordered]@{
            user        = $name
            sid         = $_.SID
            path        = $_.LocalPath
            loaded      = [bool]$_.Loaded
            lastUseTime = $(if ($_.LastUseTime) { $_.LastUseTime.ToString('yyyy-MM-ddTHH:mm:sszzz') })
            userAssist  = $null
        }
    }
})
$sidUser = @{}; foreach ($p in $profiles) { $sidUser[$p.sid] = $p.user }

# ---- prefetch -------------------------------------------------------------
$out.prefetch = Section 'prefetch' {
    $pp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction SilentlyContinue
    $files = @(Get-ChildItem -LiteralPath "$env:SystemRoot\Prefetch" -Filter '*.pf' -ErrorAction SilentlyContinue)
    $parsed = 0; $failed = 0
    foreach ($f in $files) {
        try {
            $p = [WaAppUsage]::Parse($f.FullName)
            $parsed++
            $times = @($p.RunTimes | ForEach-Object { ConvertFrom-FileTime $_ } | Where-Object { $_ } | Sort-Object -Descending)
            $path = $null
            if ($p.Paths.Count) { $path = Convert-DevicePath $p.Paths[0] }
            if (-not $path) { $path = "(prefetch)\" + $p.ExeName }
            $e = Get-Exec $path
            $rec = [ordered]@{ file = $f.Name; runCount = $p.RunCount; runTimes = $times }
            if ($e.prefetch) {
                # Same program, another prefetch file (different command line): merge.
                $e.prefetch.runCount += $p.RunCount
                $e.prefetch.runTimes = @(@($e.prefetch.runTimes) + $times | Sort-Object -Descending | Select-Object -First 8)
                $e.prefetch.file = "$($e.prefetch.file), $($f.Name)"
            } else { $e.prefetch = $rec }
            if ($times.Count) { $e.lastRun = Later $e.lastRun $times[0] }
        } catch {
            $err = "$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
            $failed++
            # Fall back to the file's own time: written on each run.
            $e = Get-Exec ("(prefetch)\" + ($f.Name -replace '-[0-9A-F]{8}\.pf$', ''))
            $t = $f.LastWriteTime.ToString('yyyy-MM-ddTHH:mm:sszzz')
            $e.prefetch = [ordered]@{ file = $f.Name; runCount = $null; runTimes = @($t); note = "unparsed: $err" }
            $e.lastRun = Later $e.lastRun $t
        }
    }
    [ordered]@{
        enablePrefetcher = $(if ($pp) { $pp.EnablePrefetcher })
        files            = $files.Count
        parsed           = $parsed
        failed           = $failed
        oldest           = $(if ($files.Count) { ($files | Sort-Object LastWriteTime | Select-Object -First 1).LastWriteTime.ToString('yyyy-MM-ddTHH:mm:sszzz') })
    }
}

# ---- UserAssist (per user) ------------------------------------------------
$known = @{
    '{6D809377-6AF0-444B-8957-A3773F02200E}' = $env:ProgramW6432
    '{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}' = ${env:ProgramFiles(x86)}
    '{F38BF404-1D43-42F2-9305-67DE0B28FC23}' = $env:SystemRoot
    '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}' = "$env:SystemRoot\System32"
    '{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}' = "$env:SystemRoot\SysWOW64"
    '{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}' = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs"
}
$userKnown = @{
    '{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}' = 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
    '{9E3995AB-1F9C-4F13-B827-48B24B6C7174}' = 'AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned'
    '{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}' = 'Desktop'
    '{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}' = 'AppData\Local'
    '{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}' = 'AppData\Roaming'
    '{FDD39AD0-238F-46AF-ADB4-6C85480369C7}' = 'Documents'
    '{374DE290-123F-4565-9164-39C4925E467B}' = 'Downloads'
}
$shell = $null
try { $shell = New-Object -ComObject WScript.Shell } catch {}

function Read-UserAssist([Microsoft.Win32.RegistryKey]$root, $prof) {
    $n = 0
    $ua = $root.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist')
    if (-not $ua) { return 0 }
    try {
        foreach ($g in $ua.GetSubKeyNames()) {
            $cnt = $ua.OpenSubKey("$g\Count")
            if (-not $cnt) { continue }
            try {
                foreach ($vn in $cnt.GetValueNames()) {
                    $data = $cnt.GetValue($vn)
                    if (-not ($data -is [byte[]]) -or $data.Length -lt 68) { continue }
                    $name = Rot13 $vn
                    if ($name -like 'UEME_*') { continue }
                    $count = [BitConverter]::ToInt32($data, 4)
                    $last = ConvertFrom-FileTime ([BitConverter]::ToInt64($data, 60))
                    if ($count -le 0 -and -not $last) { continue }
                    foreach ($k in $known.Keys) { if ($name.StartsWith($k, 'OrdinalIgnoreCase')) { $name = $known[$k] + $name.Substring($k.Length) } }
                    foreach ($k in $userKnown.Keys) { if ($name.StartsWith($k, 'OrdinalIgnoreCase')) { $name = (Join-Path $prof.path $userKnown[$k]) + $name.Substring($k.Length) } }
                    $lnk = $null
                    if ($name -match '\.lnk$' -and $shell -and (Test-Path -LiteralPath $name)) {
                        try { $t = $shell.CreateShortcut($name).TargetPath; if ($t) { $lnk = $name; $name = $t } } catch {}
                    }
                    $e = Get-Exec $name
                    $rec = [ordered]@{ user = $prof.user; runCount = $count; lastRun = $last }
                    if ($lnk) { $rec.shortcut = $lnk }
                    $e.userAssist = @($e.userAssist) + $rec
                    $e.lastRun = Later $e.lastRun $last
                    $n++
                }
            } finally { $cnt.Close() }
        }
    } finally { $ua.Close() }
    $n
}

foreach ($prof in $profiles) {
    Section "userAssist $($prof.user)" {
        if ($prof.loaded -or (Test-Path "Registry::HKEY_USERS\$($prof.sid)")) {
            $root = [Microsoft.Win32.Registry]::Users.OpenSubKey($prof.sid)
            try { $prof.userAssist = [ordered]@{ source = 'loaded hive'; entries = (Read-UserAssist $root $prof) } }
            finally { if ($root) { $root.Close() } }
            return
        }
        $hive = Join-Path $prof.path 'NTUSER.DAT'
        if (-not (Test-Path -LiteralPath $hive)) { $prof.userAssist = [ordered]@{ source = 'no NTUSER.DAT' }; return }
        $tmp = Join-Path $env:TEMP ("wa-appusage-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $tmp -Force | Out-Null
        $mount = "WA_APPUSAGE_" + [guid]::NewGuid().ToString('N').Substring(0, 8)
        try {
            # Copy the hive with its transaction logs, so the copy is complete.
            foreach ($f in @(Get-ChildItem -LiteralPath $prof.path -Force -Filter 'NTUSER.DAT*' | Where-Object { $_.Name -match '^NTUSER\.DAT(\.LOG\d*)?$' })) {
                Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $tmp $f.Name.ToUpper()) -Force
            }
            Get-ChildItem -LiteralPath $tmp -Force | ForEach-Object { $_.Attributes = 'Normal' }
            Invoke-Reg load "HKU\$mount" (Join-Path $tmp 'NTUSER.DAT')
            if (-not (Test-Path "Registry::HKEY_USERS\$mount")) { throw "could not load a copy of $hive" }
            $root = [Microsoft.Win32.Registry]::Users.OpenSubKey($mount)
            try { $prof.userAssist = [ordered]@{ source = 'copy of NTUSER.DAT'; entries = (Read-UserAssist $root $prof) } }
            finally { if ($root) { $root.Close() } }
        } finally {
            if (Test-Path "Registry::HKEY_USERS\$mount") {
                [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                Invoke-Reg unload "HKU\$mount"
                if (Test-Path "Registry::HKEY_USERS\$mount") { Start-Sleep -Seconds 2; [gc]::Collect(); Invoke-Reg unload "HKU\$mount" }
                if (Test-Path "Registry::HKEY_USERS\$mount") { $script:errors.Add("HKU\$mount (a temporary copy of $hive) is still loaded") }
            }
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---- BAM ------------------------------------------------------------------
$out.bam = Section 'bam' {
    $n = 0
    foreach ($base in 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings', 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings') {
        if (-not (Test-Path $base)) { continue }
        foreach ($k in @(Get-ChildItem $base)) {
            $sid = $k.PSChildName
            $user = $sidUser[$sid]; if (-not $user) { $user = $sid }
            foreach ($vn in $k.GetValueNames()) {
                $data = $k.GetValue($vn)
                if (-not ($data -is [byte[]]) -or $data.Length -lt 8) { continue }
                $last = ConvertFrom-FileTime ([BitConverter]::ToInt64($data, 0))
                if (-not $last) { continue }
                $e = Get-Exec (Convert-DevicePath $vn)
                $e.bam = @($e.bam) + [ordered]@{ user = $user; lastRun = $last }
                $e.lastRun = Later $e.lastRun $last
                $n++
            }
        }
    }
    [ordered]@{ entries = $n }
}

# ---- services (non-Microsoft image paths) ---------------------------------
$services = @(Section 'services' {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
        $pn = $_.PathName.Trim()
        $exe = $(if ($pn.StartsWith('"')) { $pn.Substring(1, $pn.IndexOf('"', 1) - 1) } elseif ($pn -match '^(.+?\.exe)\b') { $matches[1] } else { $pn })
        if ($exe -notlike "$env:SystemRoot\*") {
            [ordered]@{ name = S $_.Name; displayName = S $_.DisplayName; state = S $_.State; startMode = S $_.StartMode; exe = $exe }
        }
    }
})

# ---- installed applications, mapped to the evidence ----------------------
$generic = @($env:SystemRoot, $env:ProgramW6432, ${env:ProgramFiles(x86)}, $env:ProgramData,
    "$env:ProgramW6432\Common Files", "${env:ProgramFiles(x86)}\Common Files", "$env:ProgramData\Package Cache",
    "${env:ProgramFiles(x86)}\InstallShield Installation Information") | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\').ToLower() }
function Get-AppDir([string]$s) {
    if (-not $s) { return $null }
    $s = $s.Trim()
    if ($s.StartsWith('"')) { $i = $s.IndexOf('"', 1); if ($i -gt 0) { $s = $s.Substring(1, $i - 1) } }
    elseif ($s -match '^(.+?\.(exe|ico|dll))\b') { $s = $matches[1] }
    $s = ($s -replace ',-?\d+$', '').Trim()
    if ($s -match '\.(exe|ico|dll)$') { $s = Split-Path $s -Parent }
    if (-not $s -or $s -notmatch '^[A-Za-z]:\\') { return $null }
    $s = $s.TrimEnd('\')
    $l = $s.ToLower()
    if ($generic -contains $l -or $l.StartsWith("$($env:SystemRoot.ToLower())\")) { return $null }
    $s
}

$execList = @($exec.Values)
$out.applications = @(Section 'applications' {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $seen = @{}
    foreach ($p in $paths) {
        Get-ItemProperty $p -ErrorAction SilentlyContinue | Where-Object {
            # Hidden (SystemComponent) entries stay in: some real apps register that way.
            $_.DisplayName -and -not $_.ParentKeyName -and $_.ReleaseType -notmatch 'Update|Hotfix'
        } | ForEach-Object {
            $key = "$($_.DisplayName)|$($_.DisplayVersion)"
            if ($seen.ContainsKey($key)) { return }
            $seen[$key] = $true
            $dirs = @(@((Get-AppDir $_.InstallLocation), (Get-AppDir $_.DisplayIcon), (Get-AppDir $_.UninstallString)) |
                Where-Object { $_ } | Sort-Object -Unique)
            $prefixes = @($dirs | ForEach-Object { $_.ToLower() + '\' })
            $hits = @($execList | Where-Object { $pl = $_.path.ToLower(); @($prefixes | Where-Object { $pl.StartsWith($_) }).Count })
            $svc = @($services | Where-Object { $sl = $_.exe.ToLower(); @($prefixes | Where-Object { $sl.StartsWith($_) }).Count })
            $last = $null; $lastByUser = $null; $userRuns = 0; $pfRuns = 0; $users = @{}
            foreach ($h in $hits) {
                $last = Later $last $h.lastRun
                foreach ($u in @($h.userAssist)) {
                    $lastByUser = Later $lastByUser $u.lastRun; $userRuns += [int]$u.runCount
                    if ($u.user) { $users[$u.user] = Later $users[$u.user] $u.lastRun }
                }
                if ($h.prefetch -and $h.prefetch.runCount) { $pfRuns += [int]$h.prefetch.runCount }
            }
            [ordered]@{
                name           = S $_.DisplayName
                version        = S $_.DisplayVersion
                publisher      = S $_.Publisher
                hidden         = ($_.SystemComponent -eq 1)
                installDate    = S $_.InstallDate
                dirs           = $dirs
                lastRun        = $last
                lastStartedByUser = $lastByUser
                userStarts     = $userRuns
                users          = @($users.Keys | Sort-Object | ForEach-Object { [ordered]@{ user = $_; lastRun = $users[$_] } })
                prefetchRuns   = $pfRuns
                services       = @($svc | ForEach-Object { [ordered]@{ name = $_.name; state = $_.state; startMode = $_.startMode } })
                executables    = @($hits | Sort-Object { [string]$_.lastRun } -Descending | Select-Object -First 5 | ForEach-Object {
                    [ordered]@{ path = $_.path; lastRun = $_.lastRun } })
            }
        }
    }
} | Sort-Object { $_.name })

$out.profiles = $profiles
$out.services = $services
$out.executions = @($execList | Sort-Object { [string]$_.lastRun } -Descending)
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
    if (-not $OutFile) { $json }
    else {
        Write-Host "App usage saved to: $OutFile" -ForegroundColor Green
        if ($script:errors.Count) { Write-Host "$($script:errors.Count) collector error(s); see the 'errors' field." -ForegroundColor Yellow }
    }
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
}
exit 0
