<#
.SYNOPSIS
    Sets up key-based OpenSSH admin access to a Windows 10/11 machine.

.DESCRIPTION
    One-time bootstrap, run at the machine (on-site, VNC, or an existing remote
    session). Steps:

      1. Pre-checks: Windows build, domain join, pending reboot, Windows Update
         activity, AV product. A pending reboot or a busy servicing stack can
         stall the OpenSSH feature-on-demand install for many minutes.
      2. Operator admin account (-AdminUser, default 'bgadmin'). An existing
         account and its password are left alone; the script only makes sure it
         is enabled and in Administrators (by SID, so any Windows language
         works). If missing, it is created and the password is typed at the
         prompt. This is the operator's account, not the client's own admin.
         It is hidden from the sign-in screen (Winlogon SpecialAccounts
         UserList), since it is for SSH only; -ShowOnSignIn shows it again.
      3. Installs the OpenSSH Server optional feature if needed.
      4. sshd: Automatic start, started.
      5. Default SSH shell -> Windows PowerShell 5.1.
      6. -PublicKeys -> C:\ProgramData\ssh\administrators_authorized_keys, ACL
         locked to SYSTEM + Administrators (sshd ignores the file otherwise).
         Admin-group accounts read THIS file, not ~\.ssh\authorized_keys.
         Existing keys in the file are kept.
      7. Firewall: the stock OpenSSH inbound rule is set to all profiles (it
         ships Private-only, which blocks port 22 on Domain/Public networks)
         and scoped to -AllowFrom.
      8. sshd_config: a managed block turns off password logins and allows
         only -AdminUser from -AllowFrom (AllowUsers user@addr). This holds
         even when a third-party firewall (e.g. Norton) replaces Windows
         Firewall and ignores the rule from step 7. With LocalSubnet or Any
         in -AllowFrom, AllowUsers names -AdminUser without an address
         (sshd can't follow a subnet), and only the firewall limits sources. Validated with sshd -t
         (rolled back if invalid); sshd is restarted only if the file changed.
      9. Verify: service, listener, rule; prints the host key fingerprint to
         compare on the operator's first connect.

    Idempotent -- safe to re-run. Logs the run to -LogDir.

.PARAMETER Config
    Optional JSON file. Keys used: AdminUser, AllowFrom, PublicKeys, LogDir,
    ShowOnSignIn.
    Precedence: command-line argument > config file > built-in default.

.PARAMETER AdminUser
    Local admin account used for SSH. Default 'bgadmin'.

.PARAMETER AllowFrom
    Source addresses/subnets allowed to reach port 22 (array or comma-separated).
    REQUIRED -- from the command line or the config file. Behind a SNATing
    subnet router (e.g. Tailscale), this is the router's LAN address.
    Two keywords instead of (or alongside) addresses, for a first setup
    before the final source address is known:
      LocalSubnet  whatever subnet(s) the machine is on at the time
                   (Windows Firewall keyword; follows the machine when it
                   moves, e.g. from a bench to the site).
      Any          every source.
    With either, sshd's AllowUsers names -AdminUser without an address, so
    only Windows Firewall limits the source; keys-only login still applies.
    Tighten later by re-running with the final address (over SSH from that
    address is fine).

.PARAMETER PublicKeys
    SSH public keys to authorize (array or comma-separated). Defaults to the
    operator key below.

.PARAMETER LogDir
    Transcript directory. Default C:\tmp.

.PARAMETER ShowOnSignIn
    Show -AdminUser on the Windows sign-in screen. By default it is hidden
    (it is for SSH only; the client's own admin account is used at the
    console). On a workgroup machine a hidden account cannot be picked at the
    console at all, so re-run with -ShowOnSignIn if console access is needed.

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\enable-ssh-admin.ps1 -AllowFrom 192.0.2.10

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\enable-ssh-admin.ps1 -Config C:\tmp\client.json
#>

param(
    [string]$Config = "",
    [string]$AdminUser = "bgadmin",
    [string[]]$AllowFrom = @(),
    [string[]]$PublicKeys = @(
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEbE6VWMTSMGUD/X8DTWRJCYhXrJBt9arUVrEn0Noozw"
    ),
    [string]$LogDir = "C:\tmp",
    [switch]$ShowOnSignIn,
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
    foreach ($k in 'AdminUser', 'AllowFrom', 'PublicKeys', 'LogDir', 'ShowOnSignIn') {
        if (-not $PSBoundParameters.ContainsKey($k) -and $null -ne $cfg.$k) { Set-Variable -Name $k -Value $cfg.$k }
    }
}
$AllowFrom  = @($AllowFrom  | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | ForEach-Object {
    if ($_ -eq 'any') { 'Any' } elseif ($_ -eq 'localsubnet') { 'LocalSubnet' } else { $_ } })
# Any covers everything else; the firewall rejects Any mixed with addresses.
if ($AllowFrom -contains 'Any') { $AllowFrom = @('Any') }
$AllowKeyword = [bool]($AllowFrom | Where-Object { $_ -in 'Any', 'LocalSubnet' })
$PublicKeys = @($PublicKeys | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($env:SSH_CLIENT) { $NoPause = $true }

if (-not $AllowFrom)  { Write-Host "-AllowFrom is required (command line or config file)." -ForegroundColor Red; exit 2 }
if (-not $PublicKeys) { Write-Host "-PublicKeys is empty; nothing to authorize." -ForegroundColor Red; exit 2 }

$ProgressPreference = 'SilentlyContinue'

# ---- logging --------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$log = Join-Path $LogDir "enable-ssh-admin_${env:COMPUTERNAME}_${stamp}.log"
Start-Transcript -Path $log -Force | Out-Null

$script:failures = 0
function Step($msg) { Write-Host ""; Write-Host "--- $msg" -ForegroundColor Cyan }
function Ok($msg)   { Write-Host "  OK   $msg" -ForegroundColor Green }
function Warn($msg) { Write-Host "  WARN $msg" -ForegroundColor Yellow }
function Fail($msg) { Write-Host "  FAIL $msg" -ForegroundColor Red; $script:failures++ }
function Finish {
    Write-Host "Log: $log"
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
    if ($script:failures) { exit 1 } else { exit 0 }
}

Write-Host ""
Write-Host "=== enable-ssh-admin  ($env:COMPUTERNAME) ===" -ForegroundColor Cyan

# ---- 1. pre-checks --------------------------------------------------------
Step "Pre-checks"
$os = Get-CimInstance Win32_OperatingSystem
Write-Host "  OS:     $($os.Caption) build $($os.BuildNumber)"
$cs = Get-CimInstance Win32_ComputerSystem
Write-Host "  Domain: $($cs.Domain) (joined: $($cs.PartOfDomain))"

$pending = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'WindowsUpdate' }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) { $pending += 'FileRename' }
if ($pending) {
    Warn "Reboot pending ($($pending -join ', ')). The OpenSSH install may stall; consider rebooting first."
} else { Ok "No reboot pending" }

if (Get-Process -Name TiWorker, TrustedInstaller -ErrorAction SilentlyContinue) {
    Warn "Windows servicing (TiWorker/TrustedInstaller) is busy; the install may be slow."
} else { Ok "Windows servicing idle" }

try {
    $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop
    Write-Host "  AV:     $(($av.displayName | Sort-Object -Unique) -join ', ')"
    if ($av.displayName -notmatch 'Windows Defender') { Warn "Third-party AV present: if SSH logins fail later, check its firewall/blocked list for sshd.exe." }
} catch { Warn "Could not read AV products from Security Center" }

# ---- 2. local admin account ----------------------------------------------
Step "Local admin account '$AdminUser'"
$adminsGroup = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$user = Get-LocalUser -Name $AdminUser -ErrorAction SilentlyContinue
if (-not $user) {
    $pw1 = Read-Host "  New password for $AdminUser" -AsSecureString
    $pw2 = Read-Host "  Repeat password" -AsSecureString
    $b1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw1))
    $b2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw2))
    if ($b1 -ne $b2 -or -not $b1) { Fail "Passwords empty or don't match. Re-run the script."; Finish }
    $b1 = $null; $b2 = $null
    New-LocalUser -Name $AdminUser -Password $pw1 -FullName "Remote admin ($AdminUser)" `
        -Description "Operator remote management (SSH)" -PasswordNeverExpires -AccountNeverExpires | Out-Null
    Ok "Created $AdminUser"
} else {
    if (-not $user.Enabled) { Enable-LocalUser -Name $AdminUser; Ok "Enabled existing $AdminUser" }
    else { Ok "$AdminUser already exists; password unchanged" }
}
$isMember = Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "\\$([regex]::Escape($AdminUser))$" }
if (-not $isMember) {
    Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $AdminUser
    Ok "Added $AdminUser to $adminsGroup"
} else { Ok "$AdminUser is in $adminsGroup" }

# Sign-in screen visibility: a DWORD named for the account, 0 = hidden.
$userList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
$hidden = (Get-ItemProperty -Path $userList -Name $AdminUser -ErrorAction SilentlyContinue).$AdminUser
if ($ShowOnSignIn) {
    if ($null -ne $hidden) { Remove-ItemProperty -Path $userList -Name $AdminUser; Ok "$AdminUser shown on the sign-in screen again" }
    else { Ok "$AdminUser is shown on the sign-in screen (-ShowOnSignIn)" }
} elseif ($hidden -eq 0) {
    Ok "$AdminUser is hidden from the sign-in screen"
} else {
    if (-not (Test-Path $userList)) { New-Item -Path $userList -Force | Out-Null }
    New-ItemProperty -Path $userList -Name $AdminUser -PropertyType DWord -Value 0 -Force | Out-Null
    Ok "$AdminUser hidden from the sign-in screen (SSH only; -ShowOnSignIn to show it)"
}

# ---- 3. OpenSSH Server feature -------------------------------------------
Step "OpenSSH Server feature"
$cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' | Select-Object -First 1
if ($cap.State -ne 'Installed') {
    Write-Host "  Installing $($cap.Name) (can take several minutes)..."
    $r = Add-WindowsCapability -Online -Name $cap.Name
    if ($r.RestartNeeded) { Warn "Install reports a restart is needed" }
    Ok "Installed"
} else { Ok "Already installed" }

# ---- 4. sshd service -----------------------------------------------------
Step "sshd service"
Set-Service -Name sshd -StartupType Automatic
if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }
Ok "sshd $((Get-Service sshd).Status), startup Automatic"

# ---- 5. default shell ----------------------------------------------------
Step "Default SSH shell"
$psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
New-Item -Path 'HKLM:\SOFTWARE\OpenSSH' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell -Value $psExe -PropertyType String -Force | Out-Null
Ok "DefaultShell = $psExe"

# ---- 6. administrators_authorized_keys -----------------------------------
Step "Authorized keys"
$akf = "$env:ProgramData\ssh\administrators_authorized_keys"
$existing = @()
if (Test-Path $akf) { $existing = @(Get-Content $akf | Where-Object { $_.Trim() }) }
$merged = @($existing) + @($PublicKeys | Where-Object { $existing -notcontains $_ })
Set-Content -Path $akf -Value $merged -Encoding ascii
icacls $akf /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F' | Out-Null
Ok "$($merged.Count) key(s) in $akf, ACL SYSTEM + Administrators only"

# ---- 7. firewall ---------------------------------------------------------
Step "Firewall (port 22 from $($AllowFrom -join ','))"
$rule = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH SSH Server (sshd)' `
        -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any -RemoteAddress $AllowFrom | Out-Null
    Ok "Created rule"
} else {
    Set-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -Enabled True -Profile Any -RemoteAddress $AllowFrom
    Ok "Updated stock rule: all profiles, RemoteAddress $($AllowFrom -join ',')"
}
if ($AllowKeyword) {
    Warn "Port 22 is open to $($AllowFrom -join ','), not a fixed address. Fine for a first setup; re-run with the final address (e.g. the site's subnet router) to tighten it."
}

# ---- 8. sshd_config ------------------------------------------------------
Step "sshd_config (keys only; $AdminUser from $($AllowFrom -join ','))"
$sc = "$env:ProgramData\ssh\sshd_config"
$begin = '# BEGIN enable-ssh-admin (managed; re-run the script to change)'
$end   = '# END enable-ssh-admin'
# Windows sshd matches user names in lowercase.
# With LocalSubnet/Any, no address in AllowUsers: the firewall does the scoping.
$allow = if ($AllowKeyword) { $AdminUser.ToLower() } else { ($AllowFrom | ForEach-Object { "$($AdminUser.ToLower())@$_" }) -join ' ' }
# ChallengeResponseAuthentication (not its 8.7+ name KbdInteractiveAuthentication)
# so older Windows 10 OpenSSH builds accept it too.
$block = @($begin, 'PasswordAuthentication no', 'ChallengeResponseAuthentication no', "AllowUsers $allow", $end)
$old = @(Get-Content -LiteralPath $sc)
$out = New-Object System.Collections.Generic.List[string]
$inBlock = $false; $inMatch = $false
foreach ($l in $old) {
    if ($l -like '# BEGIN enable-ssh-admin*') { $inBlock = $true; continue }
    if ($l -eq $end) { $inBlock = $false; continue }
    if ($inBlock) { continue }
    if ($l -match '^\s*Match\s') { $inMatch = $true }
    # sshd takes the first value it reads, so comment out global duplicates.
    if (-not $inMatch -and $l -match '^\s*(PasswordAuthentication|ChallengeResponseAuthentication|KbdInteractiveAuthentication|AllowUsers)\s') { $l = "# $l" }
    $out.Add($l)
}
# Global directives must come before the first Match block.
$i = 0; while ($i -lt $out.Count -and $out[$i] -notmatch '^\s*Match\s') { $i++ }
$out.InsertRange($i, [string[]]$block)
if (($old -join "`n") -eq ($out -join "`n")) {
    Ok "Already restricted; unchanged"
} else {
    $bak = "$sc.bak-$stamp"
    Copy-Item -LiteralPath $sc -Destination $bak
    Set-Content -LiteralPath $sc -Value $out -Encoding ascii
    $t = & "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t 2>&1
    if ($LASTEXITCODE -ne 0) {
        Copy-Item -LiteralPath $bak -Destination $sc -Force
        Fail "sshd -t rejected the new config; restored the original. $t"
    } else {
        Ok "Password/keyboard-interactive off; AllowUsers $allow (backup: $bak)"
        Restart-Service sshd
        Ok "sshd restarted; new logins use the new config"
    }
}

# ---- 9. verify -----------------------------------------------------------
Step "Verify"
if ((Get-Service sshd).Status -eq 'Running') { Ok "sshd running" } else { Fail "sshd not running" }
if (Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue) { Ok "Listening on 22" } else { Fail "Nothing listening on 22" }
$f = Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' | Get-NetFirewallAddressFilter
Write-Host "  Rule RemoteAddress: $($f.RemoteAddress -join ',')"
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' }).IPAddress -join ', '
Write-Host "  This machine: $env:COMPUTERNAME  $ip"
$hk = "$env:ProgramData\ssh\ssh_host_ed25519_key.pub"
if (Test-Path $hk) {
    $fp = & "$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe" -lf $hk
    Write-Host "  Host key (check on first connect): $fp" -ForegroundColor White
}
Write-Host ""
Write-Host "Done. From the operator machine: ssh $AdminUser@<ip> hostname" -ForegroundColor Cyan
Finish
