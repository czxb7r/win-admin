<#
.SYNOPSIS
    Disables the Windows / NIC power-saving features that let a wired adapter
    drop its link at idle (and need a full power-cycle to recover).

.DESCRIPTION
    Companion remediation to netdrop-diag.ps1. Typical trigger: every NIC
    power-saving knob enabled, PCIe ASPM on "maximum power savings", and Fast
    Startup ON -- the textbook cause of a (often Realtek) link that dies at idle
    and only comes back after a true power-off (Fast Startup makes a normal
    shutdown a hibernate that never re-inits the NIC).

    Adapter-agnostic. It enumerates the machine's own wired adapters and applies
    only what each one supports:
      * GENERIC (any Win10/11 box):
          - "Allow the computer to turn off this device to save power"  -> OFF
            (PnPCapabilities=256 AND MSPower_DeviceEnable; Win11 26H2 ignores
            PnPCapabilities alone)
          - PCIe Link State Power Management (ASPM)                     -> OFF
          - USB selective suspend (power plan, AC + DC)                 -> OFF
          - Fast Startup (HiberbootEnabled)                             -> OFF
          - System sleep and hibernate on AC power                      -> NEVER
            (a sleeping machine is unreachable: Modern Standby keeps the
            link up but sshd stops answering. Battery (DC) timeouts are left
            alone, so a laptop still sleeps when unplugged.)
      * VENDOR-SPECIFIC (silently skipped where the property doesn't exist):
          - Energy-Efficient Ethernet (*EEE), Green Ethernet, Gigabit Lite,
            Power Saving Mode, Advanced EEE, Auto Disable Gigabit       -> OFF
          - Adapter selective suspend (*SelectiveSuspend; USB NICs)     -> OFF

    Idempotent. Prints BEFORE/AFTER and logs the run to -LogDir.
    Scope: wired (802.3) adapters only; Wi-Fi is left untouched.

    By default THE ADAPTERS ARE RELOADED (disable/enable) so the changes take
    effect at once. Run over SSH on the same NIC, the session can die mid-run
    and leave the adapter disabled, so the script refuses to run inside an SSH
    session unless -NoReload or -AllowOverSsh is given.

    Two ways to run it remotely:
      * -NoReload over plain SSH (win-run <host> disable-network-power-saving
        -NoReload): writes every setting without touching the link, then a
        reboot applies them. Use this where an EDR agent is present: EDR
        products (e.g. SentinelOne) flag a scheduled task started from a remote
        session as lateral movement and kill it.
      * win-run --as-task: one-off SYSTEM scheduled task, changes apply at
        once. Only where no EDR agent objects to remote scheduled tasks.

.PARAMETER Config
    Optional JSON file. Keys used: LogDir.

.PARAMETER LogDir
    Transcript directory. Default C:\tmp.

.PARAMETER NoReload
    Stage the changes without reloading the adapters (advanced properties are
    written with -NoRestart). Safe over SSH; the link never drops. A reboot
    applies the changes.

.PARAMETER AllowOverSsh
    Run even inside an SSH session (only safe if SSH uses a different NIC).

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\disable-network-power-saving.ps1
#>

param(
    [string]$Config = "",
    [string]$LogDir = "C:\tmp",
    [switch]$NoReload,
    [switch]$AllowOverSsh,
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

if ($env:SSH_CLIENT -and -not $AllowOverSsh -and -not $NoReload) {
    Write-Host "Refusing to run inside an SSH session: reloading the NIC can kill the session" -ForegroundColor Red
    Write-Host "and leave the adapter disabled. Pass -NoReload (then reboot), use 'win-run --as-task'," -ForegroundColor Red
    Write-Host "or pass -AllowOverSsh." -ForegroundColor Red
    exit 2
}

# ---- logging --------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$log = Join-Path $LogDir "disable-network-power-saving_${env:COMPUTERNAME}_${stamp}.log"
Start-Transcript -Path $log -Force | Out-Null

function Finish {
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
    exit 0
}

Write-Host ""
Write-Host "=== disable-network-power-saving  ($env:COMPUTERNAME) ===" -ForegroundColor Cyan
Write-Host ""

$nics = Get-NetAdapter -Physical | Where-Object { $_.PhysicalMediaType -eq '802.3' }
if (-not $nics) { Write-Host "No wired adapters found. Nothing to do."; Finish }

# ---- BEFORE snapshot ------------------------------------------------------
function Show-State($label) {
    Write-Host ""
    Write-Host "----- $label -----" -ForegroundColor Yellow
    foreach ($n in $nics) {
        Write-Host ("  [{0}]  {1}" -f $n.Name, $n.InterfaceDescription)
        try {
            $pm = Get-NetAdapterPowerManagement -Name $n.Name -ErrorAction Stop
            Write-Host ("     AllowComputerToTurnOffDevice : {0}" -f $pm.AllowComputerToTurnOffDevice)
        } catch {}
        # -eq (not -RegistryKeyword) so the '*EEE' asterisk isn't treated as a
        # wildcard and doesn't also pull in 'AdvancedEEE'.
        $props = Get-NetAdapterAdvancedProperty -Name $n.Name -AllProperties -ErrorAction SilentlyContinue
        foreach ($kw in '*EEE', 'EnableGreenEthernet', 'GreenEthernet', 'GigaLite', 'PowerSavingMode', '*SelectiveSuspend') {
            $ap = $props | Where-Object { $_.RegistryKeyword -eq $kw } | Select-Object -First 1
            if ($ap) { Write-Host ("     {0,-24} : {1}" -f $ap.DisplayName, $ap.DisplayValue) }
        }
    }
    $hb = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
    Write-Host ("  Fast Startup (HiberbootEnabled) : {0}" -f $hb)
    $usb = powercfg /query SCHEME_CURRENT $usbSub $usbSet | Select-String 'Current (AC|DC) Power Setting Index' | ForEach-Object { ("$_" -replace '.*Current (AC|DC).*0x0*([0-9a-f]+)$', '$1=$2') }
    Write-Host ("  USB selective suspend (1=on)    : {0}" -f ($usb -join ' '))
    $sl = Get-AcSeconds 'SUB_SLEEP' 'STANDBYIDLE'
    $hi = Get-AcSeconds 'SUB_SLEEP' 'HIBERNATEIDLE'
    Write-Host ("  Sleep / hibernate on AC (s, 0=never) : {0} / {1}" -f $sl, $hi)
}

function Get-AcSeconds($sub, $set) {
    $line = powercfg /query SCHEME_CURRENT $sub $set | Select-String 'Current AC Power Setting Index' | Select-Object -First 1
    if ($line -and ("$line" -match '0x([0-9a-f]+)\s*$')) { return [Convert]::ToInt64($Matches[1], 16) }
    return 'n/a'
}

# USB settings subgroup / USB selective suspend setting (no powercfg aliases)
$usbSub = '2a737441-1930-4402-8d77-b2bebba308a3'
$usbSet = '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'

Show-State "BEFORE"

# ---- helpers --------------------------------------------------------------
$classKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"

function Disable-DeviceTurnOff($nic) {
    # PnPCapabilities bit 0x100 = uncheck "Allow the computer to turn off this
    # device". Found by matching NetCfgInstanceId to the adapter's InterfaceGuid.
    $guid = $nic.InterfaceGuid
    $sub  = Get-ChildItem $classKey -ErrorAction SilentlyContinue | Where-Object {
        (Get-ItemProperty $_.PSPath -Name NetCfgInstanceId -ErrorAction SilentlyContinue).NetCfgInstanceId -eq $guid
    }
    $done = $false
    if ($sub) {
        Set-ItemProperty -Path $sub.PSPath -Name PnPCapabilities -Value 256 -Type DWord
        $done = $true
    }
    # Win11 26H2 ignores PnPCapabilities even after a reboot. MSPower_DeviceEnable
    # is what Device Manager's checkbox writes; set it too.
    try {
        $pw = Get-CimInstance -Namespace root/wmi -ClassName MSPower_DeviceEnable -ErrorAction Stop |
              Where-Object { $_.InstanceName -like ($nic.PnPDeviceID + '*') }
        if ($pw) {
            Set-CimInstance -InputObject $pw -Property @{Enable = $false } -ErrorAction Stop
            $done = $true
        }
    } catch {}
    return $done
}

function Set-AdvProp($nicName, $keyword, $value, $label) {
    try {
        Get-NetAdapterAdvancedProperty -Name $nicName -RegistryKeyword $keyword -ErrorAction Stop | Out-Null
        Set-NetAdapterAdvancedProperty -Name $nicName -RegistryKeyword $keyword -RegistryValue $value -NoRestart:$NoReload -ErrorAction Stop
        Write-Host ("       {0,-22} -> disabled" -f $label) -ForegroundColor Green
    } catch {
        Write-Host ("       {0,-22} -- not present, skipped" -f $label) -ForegroundColor DarkGray
    }
}

# ---- apply, per wired adapter --------------------------------------------
Write-Host ""
Write-Host "----- APPLYING -----" -ForegroundColor Yellow
foreach ($n in $nics) {
    Write-Host ("  [{0}]  {1}" -f $n.Name, $n.InterfaceDescription) -ForegroundColor Cyan

    if (Disable-DeviceTurnOff $n) {
        Write-Host "       Allow-turn-off-to-save-power -> disabled (PnPCapabilities=256 + MSPower_DeviceEnable)" -ForegroundColor Green
    } else {
        Write-Host "       Allow-turn-off-to-save-power -- registry key not found, skipped" -ForegroundColor DarkGray
    }

    Set-AdvProp $n.Name '*EEE'                '0' 'Energy-Efficient Eth'
    Set-AdvProp $n.Name 'EnableGreenEthernet' '0' 'Green Ethernet'
    Set-AdvProp $n.Name 'GreenEthernet'       '0' 'Green Ethernet (alt)'
    Set-AdvProp $n.Name 'GigaLite'            '0' 'Gigabit Lite'
    Set-AdvProp $n.Name 'PowerSavingMode'     '0' 'Power Saving Mode'
    Set-AdvProp $n.Name 'AdvancedEEE'         '0' 'Advanced EEE'
    Set-AdvProp $n.Name 'AutoDisableGigabit'  '0' 'Auto Disable Gigabit'
    Set-AdvProp $n.Name '*SelectiveSuspend'   '0' 'Selective Suspend'

    # Restart-NetAdapter alone does NOT refresh "allow computer to turn off this
    # device" -- only a driver reload (PnP disable/enable, or a reboot) does.
    if ($NoReload) {
        Write-Host "       (device reload skipped: -NoReload; applies at next reboot)" -ForegroundColor DarkGray
        continue
    }
    try {
        Disable-PnpDevice -InstanceId $n.PnPDeviceID -Confirm:$false -ErrorAction Stop
        Start-Sleep -Seconds 2
        Enable-PnpDevice  -InstanceId $n.PnPDeviceID -Confirm:$false -ErrorAction Stop
    } catch {
        try { Restart-NetAdapter -Name $n.Name -ErrorAction Stop }
        catch { Write-Host "       (device reload skipped -- will apply at next reboot: $_)" -ForegroundColor DarkGray }
    }
}

# ---- PCIe ASPM -> Off (active power scheme, AC + DC) ----------------------
Write-Host ""
Write-Host "  PCIe ASPM (Link State Power Management) -> Off" -ForegroundColor Green
powercfg /setacvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0 | Out-Null
powercfg /setdcvalueindex SCHEME_CURRENT SUB_PCIEXPRESS ASPM 0 | Out-Null

# ---- USB selective suspend -> Off (active power scheme, AC + DC) ----------
# Lets Windows suspend an idle USB device; a USB Ethernet adapter can drop its
# link this way. Machine-wide: affects every USB device, not just the NIC.
Write-Host "  USB selective suspend -> Off" -ForegroundColor Green
powercfg /setacvalueindex SCHEME_CURRENT $usbSub $usbSet 0 | Out-Null
powercfg /setdcvalueindex SCHEME_CURRENT $usbSub $usbSet 0 | Out-Null
powercfg /setactive SCHEME_CURRENT | Out-Null

# ---- System sleep / hibernate on AC -> never ------------------------------
# Standard for every client machine: on mains power it stays reachable for
# remote admin and backups. DC (battery) timeouts are not touched.
Write-Host "  Sleep and hibernate on AC -> never" -ForegroundColor Green
powercfg /change standby-timeout-ac 0 | Out-Null
powercfg /change hibernate-timeout-ac 0 | Out-Null

# ---- Fast Startup -> Off --------------------------------------------------
Write-Host "  Fast Startup (HiberbootEnabled) -> Off" -ForegroundColor Green
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" `
    -Name HiberbootEnabled -Value 0 -Type DWord

# ---- AFTER snapshot -------------------------------------------------------
Start-Sleep -Seconds 3
$nics = Get-NetAdapter -Physical | Where-Object { $_.PhysicalMediaType -eq '802.3' }
Show-State $(if ($NoReload) { "AFTER (staged; values shown are written, not yet live)" } else { "AFTER" })

Write-Host ""
Write-Host "Done. Log: $log" -ForegroundColor Green
if ($NoReload) {
    Write-Host "Changes are staged. REBOOT to apply them (Restart-Computer), then re-check." -ForegroundColor Yellow
} else {
    Write-Host "Fast Startup change fully applies at the NEXT shutdown." -ForegroundColor Green
}
Write-Host ""
Finish
