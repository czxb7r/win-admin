<#
.SYNOPSIS
    Joins this machine to a Tailscale tailnet with a one-time auth key, as an
    always-on (unattended) node, so it keeps a fixed tailnet address and name
    whatever address the LAN's DHCP gives it.

.DESCRIPTION
    Tailscale must already be installed (install-apps -Apps tailscale). The
    script:

      1. reads `tailscale status`; if the machine is already logged in, it
         changes nothing except re-applying -AcceptRoutes / -AcceptDns with
         `tailscale set`, and reports the node
      2. otherwise runs
             tailscale up --auth-key=file:<AuthKeyFile> --unattended --reset
                          --accept-routes=<bool> --accept-dns=<bool>
                          [--advertise-tags=<Tags>] [--hostname=<Hostname>]
         so the key is read by tailscale from the file and never appears on a
         command line or in the transcript
      3. deletes the key file whether or not the join worked
      4. reads the status again and reports address, name and tags

    The auth key is never taken on the command line. Over SSH, copy it up to
    a file first and pass -AuthKeyFile; the file is deleted after use.

    --unattended keeps the node connected when nobody is signed in to
    Windows (the point of a remote-access node). Routes and DNS are NOT
    accepted by default: a machine that sits on the same LAN as the tailnet's
    subnet router should reach that LAN directly, not through the router, and
    the machine's own DNS is left alone. Pass -AcceptRoutes / -AcceptDns (or
    TailnetAcceptRoutes / TailnetAcceptDns in the config) for a machine that
    roams and needs them.

    A node joined with tags is owned by the tags, not by a person: it takes
    no user seat and its node key does not expire. A node joined without tags
    belongs to whoever created the auth key, and its key expires (default 180
    days). The tags must be allowed for the key in the tailnet policy
    (tagOwners); create the key with them in the admin console.

    Works in a plain elevated SSH session (no SYSTEM scheduled task); the SSH
    session isn't affected because no LAN routes are accepted.

    Last line of output:
        RESULT joined=<True|False> already=<True|False> ip=<addr> name=<dnsname> tags=<tags>

.PARAMETER Config
    Optional JSON file. Keys used: LogDir, TailnetTags, TailnetAcceptRoutes,
    TailnetAcceptDns.
    Precedence: command-line argument > config file > built-in default.

.PARAMETER AuthKeyFile
    File holding the auth key (tskey-auth-...). Deleted after use. Required
    unless the machine is already logged in.

.PARAMETER Tags
    Tags to advertise, e.g. tag:workstation. A list or a comma-separated
    string; "tag:" is added if missing. Config key: TailnetTags.

.PARAMETER Hostname
    Node name on the tailnet. Default: Tailscale's own (the computer name).

.PARAMETER AcceptRoutes
    Accept subnet routes from the tailnet. Default off. Config key:
    TailnetAcceptRoutes.

.PARAMETER AcceptDns
    Accept the tailnet's DNS settings (MagicDNS). Default off. Config key:
    TailnetAcceptDns.

.PARAMETER LogDir
    Transcript directory. Default C:\tmp. The auth key is never written to it.

.PARAMETER NoPause
    Skip the closing "Press Enter" prompt. Implied when run over SSH or as SYSTEM.

.EXAMPLE
    win-run -c client.json pc01 join-tailnet -AuthKeyFile 'C:\tmp\ts-authkey.txt'

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File C:\tmp\join-tailnet.ps1 -AuthKeyFile C:\tmp\ts-authkey.txt -Tags tag:workstation
#>

param(
    [string]$Config = "",
    [string]$AuthKeyFile = "",
    [string[]]$Tags = @(),
    [string]$Hostname = "",
    [switch]$AcceptRoutes,
    [switch]$AcceptDns,
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
    # Config keys carry a Tailnet prefix, since one client file serves every script.
    $map = @{ Tags = 'TailnetTags'; AcceptRoutes = 'TailnetAcceptRoutes'; AcceptDns = 'TailnetAcceptDns' }
    foreach ($p in $map.Keys) {
        $k = $map[$p]
        if (-not $PSBoundParameters.ContainsKey($p) -and $null -ne $cfg.$k) { Set-Variable -Name $p -Value $cfg.$k }
    }
}
$isSystem = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value -eq 'S-1-5-18'
if ($env:SSH_CLIENT -or $isSystem) { $NoPause = $true }
$ProgressPreference = 'SilentlyContinue'

$Tags = @($Tags | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ } |
          ForEach-Object { if ($_ -like 'tag:*') { $_ } else { "tag:$_" } })
$routesArg = if ($AcceptRoutes) { 'true' } else { 'false' }
$dnsArg    = if ($AcceptDns) { 'true' } else { 'false' }

function Remove-KeyFile {
    if ($AuthKeyFile -and (Test-Path -LiteralPath $AuthKeyFile)) { Remove-Item -LiteralPath $AuthKeyFile -Force }
}

$ts = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
if (-not (Test-Path -LiteralPath $ts)) {
    Remove-KeyFile
    Write-Host "Tailscale is not installed ($ts). Install it first: install-apps -Apps tailscale" -ForegroundColor Red
    exit 2
}
if ($AuthKeyFile -and -not (Test-Path -LiteralPath $AuthKeyFile)) {
    Write-Host "Auth key file not found: $AuthKeyFile" -ForegroundColor Red
    exit 2
}

# ---- logging --------------------------------------------------------------
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
$log = Join-Path $LogDir "join-tailnet_${env:COMPUTERNAME}_${stamp}.log"
Start-Transcript -Path $log -Force | Out-Null

$script:rc = 0
function Finish {
    Remove-KeyFile
    Stop-Transcript | Out-Null
    if (-not $NoPause) { Read-Host "Press Enter to close" | Out-Null }
    exit $script:rc
}

function Get-TsStatus {
    $raw = & $ts status --json 2>$null
    if (-not $raw) { return $null }
    try { return (($raw | Out-String) | ConvertFrom-Json) } catch { return $null }
}

function Show-Node($st) {
    $self = $st.Self
    $v4 = @($self.TailscaleIPs | Where-Object { $_ -match '^\d+\.' }) | Select-Object -First 1
    $name = ([string]$self.DNSName).TrimEnd('.')
    $tagList = if ($self.Tags) { @($self.Tags) -join ',' } else { '' }
    Write-Host ("  address : {0}" -f $v4)
    Write-Host ("  name    : {0}" -f $name)
    Write-Host ("  tags    : {0}" -f $(if ($tagList) { $tagList } else { '(none: owned by the key creator; node key expires)' }))
    return @{ ip = $v4; name = $name; tags = $tagList }
}

Write-Host ""
Write-Host "=== join-tailnet  ($env:COMPUTERNAME) ===" -ForegroundColor Cyan
Write-Host ""
$ver = (& $ts version 2>$null | Select-Object -First 1)
Write-Host "Tailscale $ver"

$joined = $false; $already = $false; $node = @{ ip = ''; name = ''; tags = '' }

$st = Get-TsStatus
if ($st -and $st.BackendState -eq 'Running') {
    $already = $true
    Write-Host "Already logged in to $($st.CurrentTailnet.Name); not re-joining (the auth key, if any, is discarded)." -ForegroundColor Yellow
    $out = & $ts set "--accept-routes=$routesArg" "--accept-dns=$dnsArg" 2>&1
    if ($LASTEXITCODE -ne 0) { Write-Host "  tailscale set failed: $($out | Out-String)" -ForegroundColor Red; $script:rc = 1 }
    else { Write-Host "  accept-routes=$routesArg accept-dns=$dnsArg applied" }
    $node = Show-Node $st
} else {
    if (-not $AuthKeyFile) {
        Write-Host "Not logged in (state: $(if ($st) { $st.BackendState } else { 'unknown' })) and no -AuthKeyFile given." -ForegroundColor Red
        $script:rc = 2
        Finish
    }
    $upArgs = @('up', "--auth-key=file:$AuthKeyFile", '--unattended', '--reset',
                "--accept-routes=$routesArg", "--accept-dns=$dnsArg", '--timeout=90s')
    if ($Tags.Count) { $upArgs += "--advertise-tags=$($Tags -join ',')" }
    if ($Hostname) { $upArgs += "--hostname=$Hostname" }
    Write-Host ("Joining: tailscale up --auth-key=file:<key file> --unattended --reset --accept-routes={0} --accept-dns={1}{2}{3}" -f `
        $routesArg, $dnsArg, $(if ($Tags.Count) { " --advertise-tags=$($Tags -join ',')" } else { '' }),
        $(if ($Hostname) { " --hostname=$Hostname" } else { '' }))
    $out = & $ts @upArgs 2>&1
    $upRc = $LASTEXITCODE
    Remove-KeyFile
    $outText = ($out | Out-String).Trim()
    if ($outText) { Write-Host $outText }
    $st = Get-TsStatus
    if ($upRc -eq 0 -and $st -and $st.BackendState -eq 'Running') {
        $joined = $true
        Write-Host "Joined $($st.CurrentTailnet.Name)." -ForegroundColor Green
        $node = Show-Node $st
        foreach ($t in $Tags) {
            if (@($st.Self.Tags) -notcontains $t) { Write-Host "  requested tag $t is not on the node" -ForegroundColor Red; $script:rc = 1 }
        }
    } else {
        Write-Host ("Join failed (tailscale up exit {0}, state {1})." -f $upRc, $(if ($st) { $st.BackendState } else { 'unknown' })) -ForegroundColor Red
        $script:rc = 1
    }
}

Write-Host ""
Write-Host ("RESULT joined={0} already={1} ip={2} name={3} tags={4}" -f $joined, $already, $node.ip, $node.name, $node.tags)
Finish
