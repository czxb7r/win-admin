<#
.SYNOPSIS
    Creates a local user account, standard (Users) or administrator
    (Administrators), the same way Settings > Accounts > Other users does.

.DESCRIPTION
    Creates the account with the password never expiring (as Settings does),
    puts it in Users, or with -Admin in Administrators (not Users, as Settings
    does for an administrator), and clears the "password not required" flag
    that both Settings and New-LocalUser set. Groups are found by SID, so it
    works on any display language.

    The password is never taken on the command line (it would be visible in
    process listings and shell history):
      * -PasswordFile <path>: first line of the file; the file is deleted
        after reading. Over SSH, copy the file up first (the win-admin
        profile-migration skill shows how), or pipe it from a password manager.
      * otherwise, at the machine: typed twice at a prompt.

    If the account already exists, its password is left alone (unless
    -ResetPassword) and only missing group membership is added. Membership is
    never removed: if an existing account is an administrator and -Admin was
    not given, the script reports it and exits 1 rather than demoting it.

    Do not sign in to an account that a profile-migration restore is about to
    target: a first sign-in builds a fresh profile that competes with the
    restored one.

    Last line of output:
        RESULT created=<True|False> passwordset=<True|False> admin=<True|False> groups=<names>

.PARAMETER Config
    Optional JSON file. Keys used: LogDir.
    Precedence: command-line argument > config file > built-in default.

.PARAMETER Name
    Account name. Required.

.PARAMETER FullName
    Display name. Default: the account name.

.PARAMETER Description
    Account description. Default: empty.

.PARAMETER Admin
    Administrator account (Administrators) instead of a standard one (Users).

.PARAMETER PasswordFile
    File holding the password on its first line. Deleted after reading.

.PARAMETER ResetPassword
    For an existing account: set the password from -PasswordFile or a prompt.

.PARAMETER PasswordExpires
    Let the password expire under the machine's maximum password age (default
    42 days). Default: never expires, as with Settings.

.PARAMETER LogDir
    Transcript directory. Default C:\tmp. The password is never written to it.

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    win-run pc01 new-local-user -Name jdoe -FullName "Jane Doe" -PasswordFile C:\tmp\pw.txt

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\new-local-user.ps1 -Name localadmin -Admin
#>

param(
    [string]$Config = "",
    [string]$Name = "",
    [string]$FullName = "",
    [string]$Description = "",
    [switch]$Admin,
    [string]$PasswordFile = "",
    [switch]$ResetPassword,
    [switch]$PasswordExpires,
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

if (-not $Name) { Write-Host "-Name is required." -ForegroundColor Red; exit 2 }
if (-not $FullName) { $FullName = $Name }

# Read the password before the transcript starts, so nothing about it is logged.
function Read-NewPassword {
    if ($PasswordFile) {
        if (-not (Test-Path -LiteralPath $PasswordFile)) { Write-Host "Password file not found: $PasswordFile" -ForegroundColor Red; exit 2 }
        $plain = @(Get-Content -LiteralPath $PasswordFile -TotalCount 1)[0]
        Remove-Item -LiteralPath $PasswordFile -Force
        if (-not $plain) { Write-Host "Password file was empty." -ForegroundColor Red; exit 2 }
        return (ConvertTo-SecureString $plain -AsPlainText -Force)
    }
    if ($env:SSH_CLIENT -or $isSystem) { Write-Host "No console to prompt for a password: pass -PasswordFile." -ForegroundColor Red; exit 2 }
    $p1 = Read-Host "  Password for $Name" -AsSecureString
    $p2 = Read-Host "  Repeat password" -AsSecureString
    $b1 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p1))
    $b2 = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($p2))
    if ($b1 -ne $b2 -or -not $b1) { Write-Host "Passwords empty or don't match. Re-run the script." -ForegroundColor Red; exit 2 }
    return $p1
}

$existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
$pw = $null
if (-not $existing -or $ResetPassword) { $pw = Read-NewPassword }
elseif ($PasswordFile -and (Test-Path -LiteralPath $PasswordFile)) { Remove-Item -LiteralPath $PasswordFile -Force }

# ---- logging --------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$log = Join-Path $LogDir "new-local-user_${env:COMPUTERNAME}_${stamp}.log"
Start-Transcript -Path $log -Force | Out-Null

$script:rc = 0
function Finish {
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
    exit $script:rc
}

$usersSid  = 'S-1-5-32-545'
$adminsSid = 'S-1-5-32-544'
function Get-MemberOf($acctSid) {
    foreach ($g in $usersSid, $adminsSid) {
        $grp = Get-LocalGroup -SID $g
        $m = @(Get-LocalGroupMember -Group $grp -ErrorAction SilentlyContinue | Where-Object { $_.SID.Value -eq $acctSid })
        if ($m.Count) { $grp.Name }
    }
}

$created = $false; $pwSet = $false
try {
    if (-not $existing) {
        $nu = @{ Name = $Name; Password = $pw; FullName = $FullName; AccountNeverExpires = $true }
        if ($Description) { $nu.Description = $Description }
        if (-not $PasswordExpires) { $nu.PasswordNeverExpires = $true }
        $acct = New-LocalUser @nu
        $created = $true; $pwSet = $true
        Write-Host "Created $Name ($FullName)."
    } else {
        $acct = $existing
        Write-Host "$Name already exists (enabled: $($acct.Enabled)); password unchanged$(if ($ResetPassword) { ' until reset below' })."
        if ($ResetPassword) { Set-LocalUser -Name $Name -Password $pw; $pwSet = $true; Write-Host "Password reset." }
    }
    $sid = $acct.SID.Value

    $groups = @(Get-MemberOf $sid)
    $usersName = (Get-LocalGroup -SID $usersSid).Name
    $adminsName = (Get-LocalGroup -SID $adminsSid).Name
    if ($Admin) {
        if ($groups -notcontains $adminsName) { Add-LocalGroupMember -Group $adminsName -Member $Name; Write-Host "Added to $adminsName." }
        # New accounts land in neither group; an administrator from Settings is in Administrators only.
    } else {
        if ($groups -contains $adminsName) {
            Write-Host "$Name is an administrator. Not demoting it; remove it from $adminsName by hand if that is intended." -ForegroundColor Yellow
            $script:rc = 1
        } elseif ($groups -notcontains $usersName) { Add-LocalGroupMember -Group $usersName -Member $Name; Write-Host "Added to $usersName." }
    }

    # Clear UF_PASSWD_NOTREQD (0x20); both Settings and New-LocalUser set it.
    $adsi = [ADSI]"WinNT://$env:COMPUTERNAME/$Name,user"
    $flags = [int]$adsi.UserFlags.Value
    if ($flags -band 0x20) { $adsi.UserFlags.Value = $flags -band (-bnot 0x20); $adsi.SetInfo(); Write-Host "Cleared 'password not required'." }

    $acct = Get-LocalUser -Name $Name
    $groups = @(Get-MemberOf $sid)
    Write-Host ("Account: {0}  SID {1}  enabled={2}  password required={3}  password expires={4}" -f `
        $acct.Name, $sid, $acct.Enabled, $acct.PasswordRequired, $(if ($acct.PasswordExpires) { $acct.PasswordExpires } else { 'never' }))
} catch {
    Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    $script:rc = 1
}

Write-Host ("RESULT created={0} passwordset={1} admin={2} groups={3}" -f $created, $pwSet, ($groups -contains (Get-LocalGroup -SID $adminsSid).Name), ($groups -join ','))
Finish
