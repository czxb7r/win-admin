<#
.SYNOPSIS
    Collects a Windows machine's configuration inventory as JSON. Read-only.

.DESCRIPTION
    Hardware (make/model/serial, CPU, RAM modules, disks), OS (edition, display
    version, build, install date), volumes, directory join (AD / Entra), network
    adapters, BitLocker, AV / Defender / firewall, Windows Update (reboot pending,
    recent history, pending updates, policy), local users / admins / profiles,
    installed applications, remote-access services and power settings.

    Each collector is independent: a failure is recorded in the "errors" array
    and the rest still runs. Changes nothing on the machine.

    Output:
      * over SSH (win-run): JSON on stdout only; nothing is written to disk
        unless -OutFile is given.
      * at the machine: JSON saved to <LogDir>\inventory_<host>_<timestamp>.json
        (or -OutFile).
    Render it on the operator machine with bin/win-inventory-render.

.PARAMETER Config
    Optional JSON file. Keys used: LogDir, SkipUpdateSearch.

.PARAMETER OutFile
    Also write the JSON to this file.

.PARAMETER LogDir
    Directory for the default output file when run at the machine. Default C:\tmp.

.PARAMETER SkipUpdateSearch
    Skip the online Windows Update search for pending updates (can take a minute).

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    win-run pc01 get-inventory > pc01.json          (from the operator machine)

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\get-inventory.ps1
#>

param(
    [string]$Config = "",
    [string]$OutFile = "",
    [string]$LogDir = "C:\tmp",
    [switch]$SkipUpdateSearch,
    [switch]$NoPause
)

$SchemaVersion = 'win-admin/inventory/v1'

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
    foreach ($k in 'LogDir', 'SkipUpdateSearch') {
        if (-not $PSBoundParameters.ContainsKey($k) -and $null -ne $cfg.$k) { Set-Variable -Name $k -Value $cfg.$k }
    }
}
$isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
$viaSsh = [bool]$env:SSH_CLIENT
if ($viaSsh -or $isSystem) { $NoPause = $true }
if (-not $viaSsh -and -not $OutFile) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    $OutFile = Join-Path $LogDir ("inventory_{0}_{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}

# Stdout must carry nothing but JSON: silence progress/warnings, and make
# non-terminating errors throw so each Section can record them.
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'

# ---- helpers --------------------------------------------------------------
$script:errors = New-Object System.Collections.Generic.List[string]
function Section([string]$Name, [scriptblock]$Body) {
    try { & $Body } catch { $script:errors.Add("${Name}: $($_.Exception.Message)") }
}
function D($d) { if ($d) { ([datetime]$d).ToString('yyyy-MM-ddTHH:mm:ss') } }
function GB($bytes, [int]$digits = 1) { if ($null -ne $bytes) { [math]::Round([double]$bytes / 1GB, $digits) } }
function S($v) { if ($null -ne $v) { "$v".Trim() } }
function Get-PowercfgAc([string]$Sub, [string]$Setting) {
    $line = powercfg /query SCHEME_CURRENT $Sub $Setting | Select-String 'Current AC Power Setting Index' | Select-Object -First 1
    if ($line -and "$line" -match '0x([0-9a-fA-F]+)') { [Convert]::ToInt32($matches[1], 16) }
}

$cs = $null
Section 'computersystem' { $script:cs = Get-CimInstance Win32_ComputerSystem }

# ---- collectors -----------------------------------------------------------
$inv = [ordered]@{}
$inv.schema = $SchemaVersion
$inv.collected = (Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz')
$inv.collectedBy = "$env:USERDOMAIN\$env:USERNAME"

$inv.host = Section 'host' {
    $tcp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    [ordered]@{
        name             = $env:COMPUTERNAME
        dnsHostName      = S $tcp.Hostname
        primaryDnsSuffix = S $tcp.Domain
    }
}

$inv.hardware = Section 'hardware' {
    $bios = Get-CimInstance Win32_BIOS
    $cpu  = @(Get-CimInstance Win32_Processor)
    $mem  = @(Get-CimInstance Win32_PhysicalMemory)
    $enc  = Get-CimInstance Win32_SystemEnclosure
    $disks = @(Get-PhysicalDisk | Sort-Object DeviceId | ForEach-Object {
        [ordered]@{
            model     = S $_.FriendlyName
            mediaType = S $_.MediaType
            busType   = S $_.BusType
            sizeGB    = GB $_.Size 0
            health    = S $_.HealthStatus
            serial    = S $_.SerialNumber
        }
    })
    [ordered]@{
        manufacturer      = S $cs.Manufacturer
        model             = S $cs.Model
        systemFamily      = S $cs.SystemFamily
        systemSku         = S $cs.SystemSKUNumber
        chassisTypes      = @($enc.ChassisTypes)
        serial            = S $bios.SerialNumber
        biosVersion       = S $bios.SMBIOSBIOSVersion
        biosDate          = D $bios.ReleaseDate
        cpu               = [ordered]@{
            name    = S $cpu[0].Name
            sockets = $cpu.Count
            cores   = ($cpu | Measure-Object NumberOfCores -Sum).Sum
            threads = ($cpu | Measure-Object NumberOfLogicalProcessors -Sum).Sum
        }
        memoryInstalledGB = GB ($mem | Measure-Object Capacity -Sum).Sum 0
        memoryUsableGB    = GB $cs.TotalPhysicalMemory
        memoryModules     = @($mem | ForEach-Object {
            [ordered]@{
                slot         = S $_.DeviceLocator
                sizeGB       = GB $_.Capacity 0
                speedMHz     = $_.ConfiguredClockSpeed
                manufacturer = S $_.Manufacturer
                partNumber   = S $_.PartNumber
            }
        })
        disks             = $disks
    }
}

$inv.os = Section 'os' {
    $os = Get-CimInstance Win32_OperatingSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    [ordered]@{
        caption        = S $os.Caption
        edition        = S $cv.EditionID
        displayVersion = S $cv.DisplayVersion
        build          = "$($cv.CurrentBuild).$($cv.UBR)"
        architecture   = S $os.OSArchitecture
        installDate    = D $os.InstallDate
        lastBoot       = D $os.LastBootUpTime
        locale         = (Get-Culture).Name
        timeZone       = (Get-TimeZone).Id
    }
}

$inv.volumes = @(Section 'volumes' {
    Get-Volume | Where-Object { $_.DriveLetter } | Sort-Object DriveLetter | ForEach-Object {
        [ordered]@{
            letter     = "$($_.DriveLetter):"
            label      = S $_.FileSystemLabel
            fileSystem = S $_.FileSystem
            sizeGB     = GB $_.Size 0
            freeGB     = GB $_.SizeRemaining 0
        }
    }
})

$inv.join = Section 'join' {
    $ds = @{}
    dsregcmd /status | ForEach-Object { if ($_ -match '^\s*(\w+)\s*:\s*(.*?)\s*$') { $ds[$matches[1]] = $matches[2] } }
    [ordered]@{
        partOfDomain    = [bool]$cs.PartOfDomain
        domain          = $(if ($cs.PartOfDomain) { S $cs.Domain })
        workgroup       = $(if (-not $cs.PartOfDomain) { S $cs.Workgroup })
        netbiosDomain   = $ds['DomainName']
        entraJoined     = ($ds['AzureAdJoined'] -eq 'YES')
        entraTenant     = $ds['TenantName']
        workplaceJoined = ($ds['WorkplaceJoined'] -eq 'YES')
    }
}

$inv.network = @(Section 'network' {
    $mspower = @()
    try { $mspower = @(Get-CimInstance -Namespace root/wmi -ClassName MSPower_DeviceEnable) } catch {}
    Get-NetAdapter -Physical | Sort-Object ifIndex | ForEach-Object {
        $a = $_
        $ip   = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue)
        $dns  = Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $ipif = Get-NetIPInterface -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $pw   = $mspower | Where-Object { $_.InstanceName -like ($a.PnPDeviceID + '*') } | Select-Object -First 1
        $npm  = Get-NetAdapterPowerManagement -Name $a.Name -ErrorAction SilentlyContinue
        $props = @(Get-NetAdapterAdvancedProperty -Name $a.Name -AllProperties -ErrorAction SilentlyContinue)
        $adv = [ordered]@{}
        foreach ($kw in '*EEE', 'EnableGreenEthernet', 'GreenEthernet', 'GigaLite', 'PowerSavingMode', '*SelectiveSuspend') {
            $p = $props | Where-Object { $_.RegistryKeyword -eq $kw } | Select-Object -First 1
            if ($p) { $adv[$kw.TrimStart('*')] = S $p.DisplayValue }
        }
        [ordered]@{
            name              = S $a.Name
            description       = S $a.InterfaceDescription
            media             = S $a.PhysicalMediaType
            mac               = (S $a.MacAddress).Replace('-', ':').ToLower()
            status            = S $a.Status
            linkSpeed         = S $a.LinkSpeed
            ipv4              = @($ip | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
            dhcp              = $(if ($ipif) { "$($ipif.Dhcp)" -eq 'Enabled' })
            dnsServers        = @($dns.ServerAddresses)
            driverVersion     = S $a.DriverVersion
            driverDate        = S $a.DriverDate
            # Two sources for "Allow the computer to turn off this device"; they can disagree (seen on Win11 26H2).
            allowPowerOffNetAdapter = $(if ($npm) { S $npm.AllowComputerToTurnOffDevice })
            allowPowerOffMsPower    = $(if ($pw) { [bool]$pw.Enable })
            powerSavingProps  = $adv
        }
    }
})

$inv.bitlocker = @(Section 'bitlocker' {
    Get-BitLockerVolume | Sort-Object MountPoint | ForEach-Object {
        [ordered]@{
            mountPoint       = S $_.MountPoint
            volumeStatus     = S $_.VolumeStatus
            protectionStatus = S $_.ProtectionStatus
            encryptionPct    = $_.EncryptionPercentage
            method           = S $_.EncryptionMethod
            protectors       = @($_.KeyProtector | ForEach-Object { S $_.KeyProtectorType })
        }
    }
})

$inv.security = [ordered]@{}
$inv.security.antivirus = @(Section 'antivirus' {
    Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object {
        $st = [int]$_.productState
        [ordered]@{
            name     = S $_.displayName
            enabled  = ((($st -shr 12) -band 0xF) -eq 1)
            upToDate = ((($st -shr 4) -band 0xF) -eq 0)
        }
    }
})
$inv.security.defender = Section 'defender' {
    $m = Get-MpComputerStatus
    [ordered]@{
        runningMode        = S $m.AMRunningMode
        realTimeProtection = [bool]$m.RealTimeProtectionEnabled
        tamperProtected    = [bool]$m.IsTamperProtected
        productVersion     = S $m.AMProductVersion
        signatureVersion   = S $m.AntivirusSignatureVersion
        signatureUpdated   = D $m.AntivirusSignatureLastUpdated
    }
}
$inv.security.firewall = @(Section 'firewall' {
    Get-NetFirewallProfile | ForEach-Object { [ordered]@{ profile = S $_.Name; enabled = ("$($_.Enabled)" -eq 'True') } }
})

$inv.updates = [ordered]@{}
$inv.updates.rebootPending = @(Section 'rebootPending' {
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { 'CBS' }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { 'WindowsUpdate' }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) { 'FileRename' }
})
$inv.updates.policy = Section 'wuPolicy' {
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $p = Get-ItemProperty $k -ErrorAction SilentlyContinue
    $au = Get-ItemProperty "$k\AU" -ErrorAction SilentlyContinue
    [ordered]@{
        configured = [bool]$p -or [bool]$au
        wsusServer = $(if ($au -and $au.UseWUServer -eq 1) { S $p.WUServer })
        auOptions  = $(if ($au) { $au.AUOptions })
    }
}
$session = $null
Section 'wuSession' { $script:session = New-Object -ComObject Microsoft.Update.Session }
$inv.updates.recentHistory = @(Section 'wuHistory' {
    $s = $session.CreateUpdateSearcher()
    $n = $s.GetTotalHistoryCount()
    if ($n -gt 0) {
        # Skip Defender definitions and Microsoft Store app updates (titles start with a Store product ID).
        @($s.QueryHistory(0, [math]::Min($n, 300))) |
            Where-Object { $_.Title -and $_.Title -notmatch 'Security Intelligence Update|Definition Update|^9[A-Z0-9]{11}-' } |
            Select-Object -First 15 | ForEach-Object {
                [ordered]@{ title = S $_.Title; date = D $_.Date; succeeded = ($_.ResultCode -eq 2) }
            }
    }
})
if ($SkipUpdateSearch) {
    $inv.updates.pending = $null
} else {
    $inv.updates.pending = @(Section 'wuSearch' {
        $r = $session.CreateUpdateSearcher().Search("IsInstalled=0 and IsHidden=0")
        foreach ($u in $r.Updates) { [ordered]@{ title = S $u.Title; type = $(if ($u.Type -eq 2) { 'Driver' } else { 'Software' }) } }
    })
}

$inv.accounts = [ordered]@{}
$inv.accounts.localAdmins = @(Section 'localAdmins' {
    try {
        Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
            [ordered]@{ name = S $_.Name; type = S $_.ObjectClass; source = S $_.PrincipalSource }
        }
    } catch {
        # Get-LocalGroupMember fails on unresolvable (orphaned) SIDs; fall back to ADSI.
        $gname = (New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544').Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
        $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$gname,group"
        foreach ($m in @($grp.psbase.Invoke('Members'))) {
            $path = $m.GetType().InvokeMember('ADsPath', 'GetProperty', $null, $m, $null)
            $cls  = $m.GetType().InvokeMember('Class', 'GetProperty', $null, $m, $null)
            $parts = ($path -replace '^WinNT://', '').Split('/')
            [ordered]@{ name = ($parts[-2..-1] -join '\'); type = S $cls; source = 'ADSI' }
        }
    }
})
$inv.accounts.localUsers = @(Section 'localUsers' {
    Get-LocalUser | ForEach-Object {
        [ordered]@{
            name            = S $_.Name
            enabled         = [bool]$_.Enabled
            lastLogon       = D $_.LastLogon
            passwordLastSet = D $_.PasswordLastSet
            passwordExpires = D $_.PasswordExpires
        }
    }
})
$inv.accounts.profiles = @(Section 'profiles' {
    Get-CimInstance Win32_UserProfile -Filter 'Special=False' | ForEach-Object {
        $user = $null
        try { $user = (New-Object Security.Principal.SecurityIdentifier $_.SID).Translate([Security.Principal.NTAccount]).Value } catch {}
        [ordered]@{
            user    = $user
            sid     = S $_.SID
            path    = S $_.LocalPath
            lastUse = D $_.LastUseTime
            roaming = [bool]$_.RoamingConfigured
        }
    }
})

$inv.applications = @(Section 'applications' {
    $paths = @(
        @{ scope = 'machine'; path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' },
        @{ scope = 'machine'; path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' },
        @{ scope = 'user';    path = 'Registry::HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' }
    )
    $seen = @{}
    foreach ($p in $paths) {
        Get-ItemProperty $p.path -ErrorAction SilentlyContinue | Where-Object {
            $_.DisplayName -and $_.SystemComponent -ne 1 -and -not $_.ParentKeyName -and
            $_.ReleaseType -notmatch 'Update|Hotfix'
        } | ForEach-Object {
            $key = "$($_.DisplayName)|$($_.DisplayVersion)"
            if (-not $seen.ContainsKey($key)) {
                $seen[$key] = $true
                [ordered]@{
                    name        = S $_.DisplayName
                    version     = S $_.DisplayVersion
                    publisher   = S $_.Publisher
                    installDate = S $_.InstallDate
                    scope       = $p.scope
                }
            }
        }
    }
} | Sort-Object { $_.name })

$inv.remoteAccess = Section 'remoteAccess' {
    $svc = { param($n) $s = Get-Service -Name $n -ErrorAction SilentlyContinue; if ($s) { [ordered]@{ status = S $s.Status; startType = S $s.StartType } } }
    $ts = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    [ordered]@{
        sshd        = & $svc 'sshd'
        winrm       = & $svc 'WinRM'
        rdpEnabled  = $(if ($ts) { $ts.fDenyTSConnections -eq 0 })
        remoteTools = @(Get-Service | Where-Object { $_.DisplayName -match 'VNC|TeamViewer|AnyDesk|ScreenConnect|Splashtop|LogMeIn|RustDesk|Tailscale|Remote Utilities' } |
            ForEach-Object { [ordered]@{ name = S $_.Name; displayName = S $_.DisplayName; status = S $_.Status } })
    }
}

$inv.power = Section 'power' {
    $hb = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
    [ordered]@{
        fastStartup     = $(if ($null -ne $hb) { $hb -eq 1 })
        pcieAspmAc      = Get-PowercfgAc 'SUB_PCIEXPRESS' 'ASPM'
        # USB settings / USB selective suspend (no powercfg aliases): 0 off, 1 on
        usbSuspendAc    = Get-PowercfgAc '2a737441-1930-4402-8d77-b2bebba308a3' '48e6b7a6-50f5-4782-a5d4-53bb8f07e226'
        sleepAcSeconds  = Get-PowercfgAc 'SUB_SLEEP' 'STANDBYIDLE'
        hibernateAcSecs = Get-PowercfgAc 'SUB_SLEEP' 'HIBERNATEIDLE'
    }
}

$inv.errors = @($script:errors)

# ---- output ---------------------------------------------------------------
$json = $inv | ConvertTo-Json -Depth 8
if ($OutFile) {
    [IO.File]::WriteAllText($OutFile, $json, (New-Object Text.UTF8Encoding $false))
}
if ($viaSsh) {
    try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch {}
    $json
} else {
    if (-not $OutFile) { $json }
    else {
        Write-Host "Inventory saved to: $OutFile" -ForegroundColor Green
        if ($script:errors.Count) { Write-Host "$($script:errors.Count) collector error(s); see the 'errors' field." -ForegroundColor Yellow }
    }
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
}
exit 0
