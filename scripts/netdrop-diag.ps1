<#
.SYNOPSIS
    Collects network-loss diagnostics from a Windows 10/11 machine into a single zip.

.DESCRIPTION
    Built for the "machine goes unreachable (often overnight) and only a hard
    power-cycle restores it" pattern. Read-only; changes nothing.

    Prime suspects this script is built to catch:
      1. NIC power management ("Allow the computer to turn off this device to save
         power") suspending the adapter during idle / modern-standby.
      2. Fast Startup (hiberboot) leaving the NIC in a wedged state across a normal
         "shutdown" (which is really a hibernate) -- and why a full power-cycle fixes it.
      3. Sleep / modern-standby wake behavior and wake sources.
      4. Realtek/Intel NIC driver hangs (NDIS resets, link flaps).
      5. DHCP lease expiry / DNS failure while "connected but no internet".

    Each collector is independent -- one failing does not abort the run.

    ****  RUN IT WHILE THE NETWORK IS STILL BROKEN,         ****
    ****  BEFORE YOU REBOOT / POWER-CYCLE THE MACHINE.      ****
    A reboot wipes the failure state; the whole point is to capture it live.
    TIP: also run it once while the machine is HEALTHY and keep that zip.
    Diffing a healthy capture against a broken one is the fastest path to the cause.

    Output lands in <LogDir>\NetDropDiag_<host>_<timestamp>\ plus a matching .zip.

.PARAMETER Config
    Optional JSON file. Keys used: LogDir, DnsTestName, DaysBack, SupportContact.
    Precedence: command-line argument > config file > built-in default.

.PARAMETER LogDir
    Output directory. Default C:\tmp.

.PARAMETER DnsTestName
    Extra name to resolve with nslookup (e.g. the client's own domain).
    Default www.microsoft.com.

.PARAMETER DaysBack
    How many days of event logs to collect. Default 4.

.PARAMETER SupportContact
    Who to send the zip to, shown at the end. Default "your IT support contact".

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\netdrop-diag.ps1 -DnsTestName example.com
#>

param(
    [string]$Config = "",
    [string]$LogDir = "C:\tmp",
    [string]$DnsTestName = "www.microsoft.com",
    [int]$DaysBack = 4,
    [string]$SupportContact = "your IT support contact",
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
    foreach ($k in 'LogDir', 'DnsTestName', 'DaysBack', 'SupportContact') {
        if (-not $PSBoundParameters.ContainsKey($k) -and $null -ne $cfg.$k) { Set-Variable -Name $k -Value $cfg.$k }
    }
}
$isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
if ($env:SSH_CLIENT -or $isSystem) { $NoPause = $true }
$ProgressPreference = 'SilentlyContinue'

# ---- output folder --------------------------------------------------------
$stamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$host_nm = $env:COMPUTERNAME
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$outDir  = Join-Path $LogDir "NetDropDiag_${host_nm}_${stamp}"
New-Item -ItemType Directory -Path $outDir -Force | Out-Null

Write-Host ""
Write-Host "Collecting network-drop diagnostics into:" -ForegroundColor Cyan
Write-Host "  $outDir" -ForegroundColor Cyan
Write-Host ""

# ---- helper: run a collector, capture stdout+errors to a file -------------
function Collect {
    param(
        [string]$File,            # output filename (relative to $outDir)
        [string]$Title,           # console label
        [scriptblock]$Action      # code whose output is written to the file
    )
    $path = Join-Path $outDir $File
    Write-Host ("  [*] {0}" -f $Title)
    try {
        & $Action *>&1 | Out-File -FilePath $path -Encoding UTF8 -Width 4096
    } catch {
        "ERROR running collector '$Title':`n$($_ | Out-String)" |
            Out-File -FilePath $path -Encoding UTF8 -Append
    }
}

# ---- 0. run summary / system identity ------------------------------------
Collect "00_summary.txt" "System summary & uptime" {
    "===== NetDropDiag ====="
    "Captured        : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"
    "Computer        : $env:COMPUTERNAME"
    "User (elevated) : $env:USERNAME"
    ""
    $os = Get-CimInstance Win32_OperatingSystem
    "OS              : $($os.Caption) build $($os.BuildNumber) ($($os.Version))"
    "Install date    : $($os.InstallDate)"
    "Last boot       : $($os.LastBootUpTime)"
    "Uptime          : $((Get-Date) - $os.LastBootUpTime)"
    ""
    "NOTE: 'Last boot' close to now + a working network = you probably already"
    "      rebooted, which discards the failure state. Capture BEFORE rebooting."
    ""
    $cs = Get-CimInstance Win32_ComputerSystem
    "Manufacturer    : $($cs.Manufacturer)"
    "Model           : $($cs.Model)"
    $bios = Get-CimInstance Win32_BIOS
    "Serial / BIOS   : $($bios.SerialNumber) / $($bios.SMBIOSBIOSVersion)"
}

# ---- 1. current IP / adapter state (the live failure snapshot) -----------
Collect "01_ipconfig_all.txt" "ipconfig /all" { ipconfig /all }

Collect "02_netadapter.txt" "Get-NetAdapter (state, link, driver)" {
    "===== Get-NetAdapter ====="
    Get-NetAdapter -IncludeHidden | Sort-Object ifIndex |
        Format-Table Name, ifIndex, Status, AdminStatus, LinkSpeed, MacAddress, InterfaceDescription -AutoSize
    ""
    "===== Get-NetAdapter (full detail) ====="
    Get-NetAdapter -IncludeHidden | Format-List *
    ""
    "===== Driver detail ====="
    Get-NetAdapter -IncludeHidden |
        Format-List Name, DriverProvider, DriverVersion, DriverDate, DriverFileName, DriverInformation
}

Collect "03_netipconfig.txt" "Get-NetIPConfiguration (detailed)" {
    Get-NetIPConfiguration -All -Detailed | Format-List *
    ""
    "===== IP addresses ====="
    Get-NetIPAddress | Sort-Object InterfaceIndex |
        Format-Table InterfaceAlias, IPAddress, PrefixLength, AddressFamily, AddressState, PrefixOrigin, SuffixOrigin -AutoSize
}

# ---- 2. NIC POWER MANAGEMENT (prime suspect) -----------------------------
Collect "04_nic_powermgmt.txt" "NIC power management / WoL / EEE" {
    "===== Get-NetAdapterPowerManagement (per adapter) ====="
    "If 'AllowComputerToTurnOffDevice = Enabled' on the Ethernet adapter, that is"
    "very likely the overnight drop. Fix: disable-network-power-saving.ps1."
    ""
    foreach ($a in Get-NetAdapter -IncludeHidden) {
        "----- $($a.Name)  [$($a.InterfaceDescription)] -----"
        try { Get-NetAdapterPowerManagement -Name $a.Name | Format-List * } catch { "  (no power-mgmt data: $_)" }
        ""
    }
    "===== Advanced adapter properties (EEE / Green Ethernet / selective suspend) ====="
    Get-NetAdapter -IncludeHidden | ForEach-Object {
        "----- $($_.Name) -----"
        try {
            Get-NetAdapterAdvancedProperty -Name $_.Name -AllProperties |
                Format-Table DisplayName, DisplayValue, RegistryKeyword -AutoSize
        } catch { "  (none)" }
    }
    ""
    "===== Registry: 'turn off to save power' bit per NIC (PnPCapabilities) ====="
    "  bit 0x100 set in PnPCapabilities = power-off DISABLED (what we want)."
    $ck = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
    Get-ChildItem $ck -ErrorAction SilentlyContinue | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
        if ($p.DriverDesc) {
            "{0,-55} PnPCapabilities={1}" -f $p.DriverDesc, $p.PnPCapabilities
        }
    }
}

# ---- 3. POWER / SLEEP / FAST STARTUP -------------------------------------
Collect "05_power_config.txt" "Power config, sleep states, Fast Startup" {
    "===== Available sleep states (powercfg /a) ====="
    powercfg /a
    ""
    "===== Fast Startup (HiberbootEnabled) ====="
    "  1 = Fast Startup ON. This makes 'shutdown' a hibernate, so the NIC never"
    "  fully resets -- consistent with 'only a full power-cycle fixes it'."
    $hb = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -ErrorAction SilentlyContinue
    "  HiberbootEnabled = $($hb.HiberbootEnabled)"
    ""
    "===== Active power scheme + sleep/USB/PCIe settings ====="
    powercfg /getactivescheme
    $scheme = (powercfg /getactivescheme) -replace '.*GUID: ([0-9a-f-]+).*','$1'
    "----- Sleep after -----";              powercfg /query $scheme SUB_SLEEP STANDBYIDLE
    "----- Hibernate after -----";          powercfg /query $scheme SUB_SLEEP HIBERNATEIDLE
    "----- USB selective suspend -----";    powercfg /query $scheme 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226
    "----- PCIe link state power mgmt -----";powercfg /query $scheme SUB_PCIEXPRESS ASPM
    ""
    "===== Devices armed to wake the system ====="
    powercfg /devicequery wake_armed
    ""
    "===== Wake timers ====="
    powercfg /waketimers
    ""
    "===== Last wake source ====="
    powercfg /lastwake
    ""
    "===== Devices that CAN wake (wake_programmable) ====="
    powercfg /devicequery wake_programmable
}

# ---- 4. connectivity tests (auto-detect gateway) -------------------------
Collect "06_connectivity.txt" "Live connectivity tests" {
    $gw = (Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway }).IPv4DefaultGateway.NextHop | Select-Object -First 1
    $dns = (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses }).ServerAddresses | Select-Object -First 1
    "Default gateway detected : $gw"
    "First DNS server detected: $dns"
    ""
    "===== Ping default gateway ($gw) ====="
    if ($gw) { ping -n 4 $gw } else { "  (no default gateway -- adapter has no route!)" }
    ""
    "===== Ping DNS server ($dns) ====="
    if ($dns) { ping -n 4 $dns } else { "  (no DNS server configured)" }
    ""
    "===== Ping internet by IP (1.1.1.1) ====="
    ping -n 4 1.1.1.1
    ""
    "===== Ping internet by IP (8.8.8.8) ====="
    ping -n 4 8.8.8.8
    ""
    "===== DNS resolution test (Test-NetConnection www.microsoft.com) ====="
    try { Test-NetConnection www.microsoft.com -InformationLevel Detailed | Format-List * } catch { $_ }
    ""
    "===== nslookup $DnsTestName ====="
    nslookup $DnsTestName 2>&1
    ""
    "===== Network Connectivity Status Indicator (NCSI) probe ====="
    "  DNS-connected but 'no internet' = NCSI failing. Reachability below tells which."
}

# ---- 5. routing / ARP / DNS cache ----------------------------------------
Collect "07_routing_arp_dns.txt" "Route table, ARP, DNS cache/servers" {
    "===== Route table ====="; route print
    ""
    "===== ARP cache ====="; arp -a
    ""
    "===== Neighbor cache (Get-NetNeighbor) ====="
    Get-NetNeighbor -AddressFamily IPv4 | Sort-Object InterfaceIndex |
        Format-Table InterfaceAlias, IPAddress, LinkLayerAddress, State -AutoSize
    ""
    "===== DNS client servers ====="
    Get-DnsClientServerAddress | Format-Table InterfaceAlias, AddressFamily, ServerAddresses -AutoSize
    ""
    "===== DNS resolver cache ====="; ipconfig /displaydns
}

# ---- 6. TCP/IP stack config ----------------------------------------------
Collect "08_tcpip_stack.txt" "TCP global params & interface config" {
    "===== netsh int tcp show global ====="; netsh int tcp show global
    ""
    "===== netsh int ip show config ====="; netsh int ip show config
    ""
    "===== netsh int ipv4 show interfaces ====="; netsh int ipv4 show interfaces
}

# ---- 7. Wi-Fi (confirm state & catch flapping) ---------------------------
Collect "09_wlan.txt" "WLAN interfaces / settings" {
    "===== netsh wlan show interfaces ====="; netsh wlan show interfaces
    ""
    "===== netsh wlan show settings ====="; netsh wlan show settings
    ""
    "NOTE: on a wired desktop, a connected WLAN adapter alongside Ethernet can"
    "      cause routing / NLA weirdness."
}
# built-in Windows WLAN history report (last 3 days of connect/disconnect)
try {
    netsh wlan show wlanreport | Out-Null
    $rpt = "$env:ProgramData\Microsoft\Windows\WlanReport\wlan-report-latest.html"
    if (Test-Path $rpt) { Copy-Item $rpt (Join-Path $outDir "09b_wlan-report.html") -Force }
} catch {}

# ---- 8. network drivers ---------------------------------------------------
Collect "10_net_drivers.txt" "Installed network drivers" {
    "===== pnputil /enum-drivers (Net class) ====="
    $out = pnputil /enum-drivers 2>&1 | Out-String
    ($out -split "`r?`n`r?`n") | Where-Object { $_ -match 'Class Name:\s*Net' -or $_ -match 'Published Name' } | ForEach-Object { $_ }
    ""
    "===== Net PnP devices + status ====="
    Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
        Format-Table Status, Class, FriendlyName, InstanceId -AutoSize
    ""
    "===== Problem devices (any class) ====="
    Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.Status -ne 'OK' } |
        Format-Table Status, Class, FriendlyName, InstanceId -AutoSize
}

# ---- 9. EVENT LOGS -- the historical trail --------------------------------
# Look back far enough to cover last night + a few nights of the pattern.
$since = (Get-Date).AddDays(-$DaysBack)

Collect "11_events_power_sleep.txt" "Kernel-Power / sleep-wake / dirty shutdown events" {
    "Events since $since (last $DaysBack days). Watch for:"
    "  Kernel-Power 41  = system rebooted without clean shutdown (e.g. a hard power-cycle)"
    "  Kernel-Power 42  = entering sleep;  107 = resume from sleep"
    "  Power-Troubleshooter 1 = what WOKE the machine (wake source)"
    "  EventLog 6008    = previous shutdown was unexpected"
    ""
    $ids = @{ LogName='System'; StartTime=$since;
              ProviderName='Microsoft-Windows-Kernel-Power','Microsoft-Windows-Kernel-General','Microsoft-Windows-Kernel-Boot','Microsoft-Windows-Power-Troubleshooter','USER32','EventLog' }
    Get-WinEvent -FilterHashtable $ids -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated |
        Format-Table TimeCreated, Id, ProviderName, @{n='Msg';e={($_.Message -split "`r?`n")[0]}} -AutoSize -Wrap
}

Collect "12_events_network.txt" "Network stack / NIC driver / DHCP / DNS events" {
    "Events since $since. Watch for NDIS link-down/reset, DHCP NACK/lease-fail,"
    "Tcpip address conflicts, and NIC-driver (Realtek/Intel) errors."
    ""
    $providers = 'Microsoft-Windows-NDIS','Microsoft-Windows-Dhcp-Client','Microsoft-Windows-Dhcpv6-Client',
                 'Microsoft-Windows-DNS-Client','Microsoft-Windows-Tcpip','Microsoft-Windows-NlaSvc',
                 'Microsoft-Windows-NCSI','Microsoft-Windows-WLAN-AutoConfig','Microsoft-Windows-Netwtw',
                 'e1dexpress','e2fexpress','rt640x64','RtkBtManServ','netbt','Tcpip','Dhcp'
    foreach ($p in $providers) {
        try {
            $ev = Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$since; ProviderName=$p } -ErrorAction Stop
            if ($ev) {
                "===== $p ($($ev.Count) events) ====="
                $ev | Sort-Object TimeCreated |
                    Format-Table TimeCreated, Id, LevelDisplayName, @{n='Msg';e={($_.Message -split "`r?`n")[0]}} -AutoSize -Wrap
                ""
            }
        } catch {}
    }
}

Collect "13_events_system_errors.txt" "All System log Errors & Warnings" {
    "All Level=Error(2)/Warning(3) System events since $since -- catch-all for"
    "anything the targeted providers above miss (unknown driver names, etc.)."
    ""
    Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=$since; Level=2,3 } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated |
        Format-Table TimeCreated, Id, LevelDisplayName, ProviderName, @{n='Msg';e={($_.Message -split "`r?`n")[0]}} -AutoSize -Wrap
}

Collect "14_events_wlan_operational.txt" "WLAN-AutoConfig operational log" {
    Get-WinEvent -FilterHashtable @{ LogName='Microsoft-Windows-WLAN-AutoConfig/Operational'; StartTime=$since } -ErrorAction SilentlyContinue |
        Sort-Object TimeCreated |
        Format-Table TimeCreated, Id, LevelDisplayName, @{n='Msg';e={($_.Message -split "`r?`n")[0]}} -AutoSize -Wrap
}

# ---- 10. built-in energy / battery report (modern-standby detail) --------
try {
    powercfg /sleepstudy /output (Join-Path $outDir "15_sleepstudy.html") 2>&1 | Out-Null
} catch {}
try {
    powercfg /energy /output (Join-Path $outDir "16_energy-report.html") /duration 60 2>&1 | Out-Null
} catch {}

# ---- zip it up ------------------------------------------------------------
Write-Host ""
Write-Host "  [*] Compressing..." -ForegroundColor Cyan
$zip = "$outDir.zip"
try {
    if (Test-Path $zip) { Remove-Item $zip -Force }
    Compress-Archive -Path $outDir -DestinationPath $zip -Force
} catch {
    Write-Host "  (zip failed -- just send the folder): $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
Write-Host " DONE. Send $SupportContact this file:" -ForegroundColor Green
Write-Host "   $zip" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Reminder: if you captured this AFTER rebooting, the failure state is"
Write-Host "gone. Next time it drops overnight, run this BEFORE the power-cycle."
Write-Host ""
if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
