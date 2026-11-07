<#
.SYNOPSIS
    Checks and repairs a user profile restored from another computer (e.g. with
    ForensiT Transwiz), before the user's first sign-in on the new machine.

.DESCRIPTION
    A profile restored by a migration tool can look complete and still be
    broken in ways that only show after sign-in. Seen with Transwiz 1.19.1099
    restoring a Windows 11 profile onto Windows 11 24H2:

      1. The user's UsrClass.dat is left loaded in the registry after the tool
         exits (under a GUID name). At sign-in Windows cannot load it and gives
         the user a TEMPORARY profile ("We can't sign in to your account").
      2. Registry permissions are only partly translated: keys still grant
         access to the OLD computer's account instead of the new one, so the
         user cannot change many of their own settings.
      3. File and URL associations (UserChoice keys) point at app IDs from the
         old computer and carry hashes made for the old account. Windows keeps
         resetting them ("An app default was reset"), Explorer redraws every
         icon each time, desktop shortcuts flash about once a second, and
         Settings > Default apps choices do not stick.
      4. AppData\Local\Packages is copied without the per-app permissions
         Windows gives each app, so built-in apps ask for access to their own
         files ("Let Windows Feature Experience Pack access the file ...
         settings.dat?").

    In that order this script: unloads anything left loaded (1); checks every
    key of NTUSER.DAT and UsrClass.dat and, if keys grant only another account,
    rewrites the old account's SID to the user's in owners and permissions,
    after copying both files aside (2); exports and deletes every UserChoice
    and UserChoiceLatest key, so Windows uses this computer's defaults (3);
    renames Packages if any app's Settings folder lacks its per-app grant, so
    Windows rebuilds it at first sign-in (4). Data is never deleted: hive
    files, associations and the Packages folder are all kept as backups.

    The user must be signed out (better: never signed in yet). Five of the
    association keys (.pdf .htm .html http https) are guarded by the User
    Choice Protection Driver (UCPD); while it runs, neither the migration tool
    nor this script can change them. Stop it first with set-ucpd.ps1 -Disable
    and a restart, before the restore if possible; re-enable it afterwards.

    Last line of output:
        RESULT unloaded=<n> brokenkeys=<n> fixedkeys=<n> associations=<n> assocfailed=<n> packagesbad=<n> packagesrenamed=<True|False>

.PARAMETER Config
    Optional JSON file. Keys used: LogDir.
    Precedence: command-line argument > config file > built-in default.

.PARAMETER User
    Local account whose profile to check/repair. Required.

.PARAMETER CheckOnly
    Report only; change nothing (leftover loaded files are reported, not
    unloaded). Exits 1 if anything is left loaded, any key grants only another
    account, or any app Settings folder lacks its permission.

    Repair mode clears ALL association keys. Run it only on a freshly restored
    profile, before the user's first sign-in; on a profile already in use it
    would also clear the user's own defaults.

.PARAMETER OldSid
    SID of the account on the old computer. Default: detected, as the most
    common unresolvable user SID in the profile's registry permissions.

.PARAMETER SkipAssociations
    Leave UserChoice keys alone.

.PARAMETER SkipPackages
    Leave AppData\Local\Packages alone.

.PARAMETER LogDir
    Transcript directory. Default C:\tmp.

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    win-run pc01 repair-restored-profile -User jdoe -CheckOnly

.EXAMPLE
    win-run pc01 repair-restored-profile -User jdoe
#>

param(
    [string]$Config = "",
    [string]$User = "",
    [switch]$CheckOnly,
    [string]$OldSid = "",
    [switch]$SkipAssociations,
    [switch]$SkipPackages,
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

if (-not $User) { Write-Host "-User is required." -ForegroundColor Red; exit 2 }

# ---- logging --------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$log = Join-Path $LogDir "repair-restored-profile_${env:COMPUTERNAME}_${stamp}.log"
Start-Transcript -Path $log -Force | Out-Null

$script:rc = 0
function Finish {
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
    exit $script:rc
}

Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class RrpPriv {
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr h, int acc, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool LookupPrivilegeValue(string sys, string name, out long luid);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr tok, bool all, ref TP nw, int len, IntPtr prev, IntPtr rl);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [StructLayout(LayoutKind.Sequential, Pack=1)] struct TP { public int Count; public long Luid; public int Attr; }
    public static bool Enable(string name) {
        IntPtr tok; if (!OpenProcessToken(GetCurrentProcess(), 0x28, out tok)) return false;
        TP tp = new TP(); tp.Count = 1; tp.Attr = 2;
        if (!LookupPrivilegeValue(null, name, out tp.Luid)) return false;
        return AdjustTokenPrivileges(tok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero) && Marshal.GetLastWin32Error() == 0;
    }
}
'@

# Load a hive file (or reuse it where it is already loaded), run $Body with the
# PowerShell path of its root, unload it again if this function loaded it.
function Use-Hive($File, $Loaded, [scriptblock]$Body) {
    $mount = $null; $mine = $false
    if ($Loaded.ContainsKey($File.ToLower())) { $mount = $Loaded[$File.ToLower()] }
    else {
        $mount = "RRP_" + [guid]::NewGuid().ToString('N').Substring(0, 8)
        $null = reg load "HKU\$mount" $File 2>&1
        if (-not (Test-Path "Registry::HKEY_USERS\$mount")) { throw "could not load $File" }
        $mine = $true
    }
    try { & $Body "Registry::HKEY_USERS\$mount" $mount }
    finally {
        if ($mine) {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers(); Start-Sleep -Seconds 1
            $null = reg unload "HKU\$mount" 2>&1
            if (Test-Path "Registry::HKEY_USERS\$mount") { Start-Sleep -Seconds 3; [gc]::Collect(); $null = reg unload "HKU\$mount" 2>&1 }
            if (Test-Path "Registry::HKEY_USERS\$mount") {
                Write-Host "  WARNING: HKU\$mount is still loaded. Run 'reg unload HKU\$mount' before the user signs in." -ForegroundColor Red
                $script:rc = 1
            }
        }
    }
}

function Test-ProtectedAssoc($path) { return ($path -match '\\(UserChoice|UserChoiceLatest)$') }

$unloaded = 0; $brokenKeys = 0; $fixedKeys = 0; $assocDeleted = 0; $assocFailed = 0; $pkgBad = 0; $pkgRenamed = $false

try {
    # ---- 0. account and profile --------------------------------------------
    $acct = Get-LocalUser -Name $User -ErrorAction SilentlyContinue
    if (-not $acct) { Write-Host "No local account '$User'." -ForegroundColor Red; $script:rc = 2; Finish }
    $sid = $acct.SID.Value
    $plk = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
    if (-not (Test-Path $plk)) { Write-Host "No profile registered for $User (restore not done?)." -ForegroundColor Red; $script:rc = 2; Finish }
    $prof = (Get-ItemProperty $plk).ProfileImagePath
    $up = Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }
    if (($up -and $up.Loaded) -or (Test-Path "Registry::HKEY_USERS\$sid")) {
        Write-Host "$User is signed in (profile loaded). Sign out first." -ForegroundColor Red; $script:rc = 2; Finish
    }
    $ucpd = (sc.exe query UCPD | Out-String) -match 'RUNNING'
    Write-Host "User: $User  SID: $sid  Profile: $prof"
    Write-Host ("Mode: {0}   UCPD running: {1}" -f $(if ($CheckOnly) { 'check only' } else { 'repair' }), $ucpd)
    if (Test-Path "$plk.bak") { Write-Host "  NOTE: a ProfileList '.bak' entry exists - the user has already had a temporary profile." -ForegroundColor Yellow }

    $ntuser = Join-Path $prof 'NTUSER.DAT'
    $usrclass = Join-Path $prof 'AppData\Local\Microsoft\Windows\UsrClass.dat'

    # ---- 1. registry files left loaded ---------------------------------------
    Write-Host ""
    Write-Host "== 1. Profile registry files left loaded"
    $loaded = @{}
    $hl = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\hivelist'
    $leaf = Split-Path $prof -Leaf
    $foundLoaded = $false
    foreach ($p in $hl.PSObject.Properties) {
        $v = "$($p.Value)".TrimEnd([char]0, [char]32)    # values end in a NUL
        if ($p.Name -notlike '\REGISTRY\USER\*' -or $v -notlike "*\Users\$leaf\*") { continue }
        $file = Join-Path $prof ($v.Substring($v.IndexOf("\Users\$leaf\") + "\Users\$leaf\".Length))
        $key = $p.Name -replace '^\\REGISTRY\\USER\\', ''
        $foundLoaded = $true
        Write-Host "  HKU\$key  <-  $file"
        if ($CheckOnly) { $loaded[$file.ToLower()] = $key; $script:rc = 1; continue }
        $null = reg unload "HKU\$key" 2>&1
        if (Test-Path "Registry::HKEY_USERS\$key") { Write-Host "    could not unload" -ForegroundColor Red; $script:rc = 1; $loaded[$file.ToLower()] = $key }
        else { Write-Host "    unloaded"; $unloaded++ }
    }
    if (-not $foundLoaded) { Write-Host "  none" }

    # ---- 2. registry permissions ---------------------------------------------
    Write-Host ""
    Write-Host "== 2. Registry permissions"
    $unresolved = @{}
    $scan = {
        param($root, $mount)
        $n = 0; $bad = 0
        foreach ($k in @(Get-Item $root) + @(Get-ChildItem $root -Recurse -ErrorAction SilentlyContinue)) {
            $n++
            try {
                $sd = $k.GetAccessControl('Owner, Access')
                $rules = $sd.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                $mineOk = $rules | Where-Object { $_.IdentityReference.Value -eq $sid -and $_.AccessControlType -eq 'Allow' }
                $others = @($rules | Where-Object { $_.IdentityReference.Value -like 'S-1-5-21-*' -and $_.IdentityReference.Value -ne $sid })
                $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
                foreach ($s in @($others | ForEach-Object { $_.IdentityReference.Value }) + @($owner)) {
                    if ($s -like 'S-1-5-21-*' -and $s -ne $sid) {
                        try { $null = ([System.Security.Principal.SecurityIdentifier]$s).Translate([System.Security.Principal.NTAccount]) } catch { $unresolved[$s] = 1 + [int]$unresolved[$s] }
                    }
                }
                if (-not $mineOk -and $others.Count -and -not (Test-ProtectedAssoc $k.Name)) { $bad++ }
            } catch { }
            $k.Dispose()
        }
        return @($n, $bad)
    }
    $results = @{}
    foreach ($f in $ntuser, $usrclass) {
        if (-not (Test-Path -LiteralPath $f)) { Write-Host "  $(Split-Path $f -Leaf): missing" -ForegroundColor Yellow; continue }
        $r = Use-Hive $f $loaded $scan
        $results[$f] = $r
        $brokenKeys += $r[1]
        Write-Host ("  {0,-12} {1,6} keys, {2,6} grant only another account" -f (Split-Path $f -Leaf), $r[0], $r[1])
    }
    if (-not $OldSid -and $unresolved.Count) {
        # The old account: most frequent unresolvable SID with a user RID (>= 1000).
        $OldSid = ($unresolved.GetEnumerator() | Where-Object { [int64]($_.Key -split '-')[-1] -ge 1000 } |
            Sort-Object Value -Descending | Select-Object -First 1).Key
    }
    if ($unresolved.Count) { Write-Host ("  unresolvable SIDs in the profile: {0}" -f (($unresolved.Keys | Sort-Object) -join ', ')) }
    if ($OldSid) { Write-Host "  old account SID: $OldSid" }

    if ($brokenKeys -and -not $CheckOnly) {
        if (-not $OldSid) { Write-Host "  Cannot tell the old account's SID; pass -OldSid." -ForegroundColor Red; $script:rc = 1 }
        else {
            Write-Host "  Repairing: $OldSid -> $sid in owners and permissions"
            foreach ($p in 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege', 'SeBackupPrivilege') {
                if (-not [RrpPriv]::Enable($p)) { Write-Host "  could not enable $p" -ForegroundColor Red }
            }
            $rights = [System.Security.AccessControl.RegistryRights]'ReadKey, ChangePermissions, TakeOwnership'
            $sect = [System.Security.AccessControl.AccessControlSections]'Owner, Access'
            foreach ($f in $ntuser, $usrclass) {
                if (-not (Test-Path -LiteralPath $f)) { continue }
                $bak = "$f.pre-repair-$stamp"
                Copy-Item -LiteralPath $f -Destination $bak -Force
                Write-Host "  backup: $bak"
                $fix = {
                    param($root, $mount)
                    $done = 0; $errs = 0
                    $stack = New-Object System.Collections.Stack
                    $stack.Push($mount)
                    while ($stack.Count) {
                        $path = $stack.Pop(); $k = $null
                        try {
                            # ReadWriteSubTree: .NET refuses SetAccessControl on a key it thinks is read-only.
                            $k = [Microsoft.Win32.Registry]::Users.OpenSubKey($path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
                            if (-not $k) { continue }
                            foreach ($s in $k.GetSubKeyNames()) { $stack.Push("$path\$s") }
                            $sd = $k.GetAccessControl($sect)
                            $sddl = $sd.GetSecurityDescriptorSddlForm($sect)
                            if ($sddl.Contains($OldSid)) {
                                $sd.SetSecurityDescriptorSddlForm($sddl.Replace($OldSid, $sid), $sect)
                                $k.SetAccessControl($sd)
                                $done++
                            }
                        } catch { if (-not (Test-ProtectedAssoc $path)) { $errs++ } }
                        finally { if ($k) { $k.Dispose() } }
                    }
                    return @($done, $errs)
                }
                $r = Use-Hive $f $loaded $fix
                $fixedKeys += $r[0]
                Write-Host ("  {0,-12} {1,6} keys rewritten, {2} errors" -f (Split-Path $f -Leaf), $r[0], $r[1])
            }
            $brokenKeys = 0
            foreach ($f in $ntuser, $usrclass) {
                if (-not (Test-Path -LiteralPath $f)) { continue }
                $r = Use-Hive $f $loaded $scan
                $brokenKeys += $r[1]
            }
            Write-Host "  after repair: $brokenKeys keys grant only another account"
            if ($brokenKeys) { $script:rc = 1 }
        }
    } elseif ($brokenKeys) { $script:rc = 1 }

    # ---- 3. file and URL associations --------------------------------------
    Write-Host ""
    Write-Host "== 3. File and URL associations (UserChoice)"
    if ($SkipAssociations) { Write-Host "  skipped" }
    else {
        $assoc = {
            param($root, $mount)
            $fe = "$root\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts"
            $ua = "$root\Software\Microsoft\Windows\Shell\Associations\UrlAssociations"
            $found = @()
            foreach ($r in $fe, $ua) {
                foreach ($k in @(Get-ChildItem $r -ErrorAction SilentlyContinue)) {
                    foreach ($lf in 'UserChoice', 'UserChoiceLatest') { $p = Join-Path $k.PSPath $lf; if (Test-Path $p) { $found += $p } }
                    $k.Dispose()
                }
            }
            if ($CheckOnly) { return @($found.Count, 0, 0) }
            foreach ($pair in @(@($fe, 'FileExts'), @($ua, 'UrlAssociations'))) {
                if (Test-Path $pair[0]) {
                    $null = reg export ($pair[0] -replace '^Registry::HKEY_USERS', 'HKU') (Join-Path $prof "assoc-backup-$($pair[1])-$stamp.reg") /y 2>&1
                }
            }
            $ok = 0; $failed = @()
            foreach ($p in $found) {
                try { Remove-Item $p -Recurse -Force -ErrorAction Stop; $ok++ }
                catch { $failed += ($p -replace '^.*\\(FileExts|UrlAssociations)\\', '') }
            }
            foreach ($x in $failed) { Write-Host "  could not delete $x" -ForegroundColor Yellow }
            return @($found.Count, $ok, $failed.Count)
        }
        $r = Use-Hive $ntuser $loaded $assoc
        $assocDeleted = $r[1]; $assocFailed = $r[2]
        if ($CheckOnly) {
            Write-Host "  $($r[0]) association keys present. On a freshly restored profile they all come from the old"
            Write-Host "  computer and repair mode clears them; on a profile already in use they are the user's own defaults."
        }
        else {
            Write-Host "  $assocDeleted deleted, $assocFailed failed; backups: $prof\assoc-backup-*-$stamp.reg"
            if ($assocFailed) {
                $script:rc = 1
                if ($ucpd) { Write-Host "  UCPD is running: stop it (set-ucpd -Disable, restart) and run this script again." -ForegroundColor Yellow }
            }
        }
    }

    # ---- 4. app Packages folder ------------------------------------------
    Write-Host ""
    Write-Host "== 4. App Packages folder (per-app permissions)"
    $pk = Join-Path $prof 'AppData\Local\Packages'
    if (-not (Test-Path -LiteralPath $pk)) { Write-Host "  no Packages folder (Windows creates it at first sign-in)" }
    else {
        # Windows grants each app (S-1-15-...) on its Settings folder; a copied folder lacks it.
        $settings = @(Get-ChildItem -LiteralPath $pk -Directory -Force | ForEach-Object { Join-Path $_.FullName 'Settings' } | Where-Object { Test-Path -LiteralPath $_ })
        $pkgBad = @($settings | Where-Object { -not ((Get-Acl -LiteralPath $_).Access | Where-Object { $_.IdentityReference.Value -like 'S-1-15-*' }) }).Count
        Write-Host "  $pkgBad of $($settings.Count) app Settings folders lack their per-app permission"
        if ($pkgBad -and -not $SkipPackages -and -not $CheckOnly) {
            $dest = "Packages.pre-repair-$stamp"
            Rename-Item -LiteralPath $pk -NewName $dest -ErrorAction Stop
            $pkgRenamed = $true
            Write-Host "  renamed to $dest; Windows rebuilds Packages at first sign-in"
            Write-Host "  Start menu pins: copy Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin back after the first sign-in (user signed out)."
        } elseif ($pkgBad -and $SkipPackages) { Write-Host "  skipped" }
        if ($pkgBad -and $CheckOnly) { $script:rc = 1 }
    }
} catch {
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    $script:rc = 1
}

Write-Host ""
Write-Host ("RESULT unloaded={0} brokenkeys={1} fixedkeys={2} associations={3} assocfailed={4} packagesbad={5} packagesrenamed={6}" -f `
    $unloaded, $brokenKeys, $fixedKeys, $assocDeleted, $assocFailed, $pkgBad, $pkgRenamed)
Finish
