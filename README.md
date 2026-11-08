# win-admin

Client-portable Windows administration toolkit: generic PowerShell scripts that run on the Windows machine, plus a Mac-side runner (`bin/win-run`) that ships and runs them over SSH.

Nothing here is specific to one site or client. Per-client values (subnet router address, DNS names, contact) live in each client's own repo as a JSON config file and are passed in at run time.

## Layout

| Path | What |
|---|---|
| `scripts/` | PowerShell scripts that run **on the Windows machine** (Windows PowerShell 5.1, Win10/11), plus companion data files (`<script>.*.json`, e.g. `install-apps.catalog.json`) |
| `bin/win-run` | Mac/Linux runner: upload a script (+ optional config) over SSH, run it, return its exit code, clean up |
| `bin/win-inventory-render` | Mac/Linux: render `get-inventory` JSON files as a Markdown table, one column per host (`-c client.json` for `AppsOfNote`, `--apps` for full app lists). Shares flag a **whole drive** shared; listening ports leave out Windows' own (RPC, SMB, NetBIOS, dynamic RPC); files from before a field existed show "not collected" |
| `bin/win-usb-kit` | Mac: build the USB kit (pick the drive from a list; it does the rest), see [Discovery from a flash drive](#discovery-from-a-flash-drive) |
| `usb/` | The USB kit's launchers, for a machine without SSH: `discovery.cmd` (collect) and `enable-ssh.cmd` (set up SSH); see [Discovery from a flash drive](#discovery-from-a-flash-drive) |
| `config/example.json` | Every config key any script understands, with placeholder values |
| `tools/check` | Pre-commit check: ASCII-only + PowerShell parse check (`pwsh`); companion JSON files ASCII-only + valid JSON |

## Scripts

| Script | Changes config? | Purpose |
|---|---|---|
| [`enable-ssh-admin.ps1`](scripts/enable-ssh-admin.ps1) | **Yes** | One-time bootstrap of key-based OpenSSH admin access: operator account in Administrators and hidden from the sign-in screen (`-ShowOnSignIn` to show it), OpenSSH Server, PowerShell as default shell, `administrators_authorized_keys` with locked ACL, firewall rule on all profiles scoped to `-AllowFrom`, and an `sshd_config` block that turns off password/keyboard-interactive logins and allows only the admin user from `-AllowFrom` (`AllowUsers user@addr`; holds even where a third-party firewall such as Norton ignores the Windows rule). Validated with `sshd -t`, rolled back if invalid. Prints the host-key fingerprint. Requires `-AllowFrom`: addresses, or the keywords `LocalSubnet` / `Any` for a first setup before the final source is known (then `AllowUsers` names the user without an address and only the firewall limits sources; re-run with the final address to tighten). |
| [`disable-network-power-saving.ps1`](scripts/disable-network-power-saving.ps1) | **Yes** | Turns off NIC/OS power saving that kills a wired link at idle (allow-turn-off, EEE/Green Ethernet, adapter and USB selective suspend, PCIe ASPM, Fast Startup), and sets sleep and hibernate on AC power to never, the standard for every client machine (battery timeouts untouched). Reloads the adapters by default, so over SSH either pass `-NoReload` (stages the changes, then reboot) or use `win-run --as-task`. Behind an EDR agent use `-NoReload` (see below). |
| [`install-apps.ps1`](scripts/install-apps.ps1) | **Yes** | Installs a site's standard applications (`-Apps`, or `Apps` in the config) from the vendors' own MSI packages, machine-wide and silent. Which applications exist, and where each comes from, is in the catalog [`install-apps.catalog.json`](scripts/install-apps.catalog.json) next to the script (see [Application catalog](#application-catalog)). Skips anything already installed (machine-wide uninstall entry), downloads over HTTPS, refuses to install unless the Authenticode signature is Valid and names the catalog's publisher (or, for a vendor that doesn't sign, the file matches the catalog's pinned SHA-256), runs `msiexec /qn /norestart` (verbose MSI log in `-LogDir`), then checks the uninstall entry. Works in a plain SSH session (no `--as-task`), so it can be used behind an EDR agent. Ends with `RESULT requested= installed= present= failed= reboot=`. |
| [`install-updates.ps1`](scripts/install-updates.ps1) | **Yes** | One Windows Update cycle through the Windows Update Agent API: search, download, install everything Windows would install on its own (security/cumulative updates, automatic drivers and firmware); optional updates are listed, never installed. Never reboots; ends with a machine-readable `RESULT pending= installed= failed= optional= hidden= reboot=` line, so it can be run in a loop with reboots in between until `pending=0`. `-ScanOnly` lists only. `-Hide`/`-Unhide` (title, wildcards) stop or restore an update that installs "Succeeded" but is offered again every scan. Everything except `-ScanOnly` must run as SYSTEM (Windows Update returns access denied to an SSH logon), so over SSH use `win-run --as-task --timeout 3600`; behind an EDR agent, scan over SSH and install at the machine. |
| [`new-local-user.ps1`](scripts/new-local-user.ps1) | **Yes** | Creates a local account the way Settings > Accounts does: password never expires (`-PasswordExpires` to let it), member of Users, or with `-Admin` of Administrators (groups found by SID, so any display language), and clears the "password not required" flag that both Settings and `New-LocalUser` set. The password comes from `-PasswordFile` (first line; the file is deleted after reading) or a prompt at the machine, never the command line, and never reaches the transcript. An existing account keeps its password (unless `-ResetPassword`) and only gains missing membership; an administrator is never demoted (exit 1). Ends with `RESULT created= passwordset= admin= groups=`. |
| [`set-ucpd.ps1`](scripts/set-ucpd.ps1) | **Yes** | Shows (no switch), disables (`-Disable`) or re-enables (`-Enable`) the User Choice Protection Driver (UCPD), which blocks every program except Settings, profile-migration tools included, from changing the `.pdf .htm .html http https` default-app keys. Sets the driver's start type and the scheduled task that turns it back on; takes effect after a restart, which it never does itself. Ends with `RESULT present= start= task= running= reboot=`. |
| [`repair-restored-profile.ps1`](scripts/repair-restored-profile.ps1) | **Yes** | Checks (`-CheckOnly`, exit 1 on any problem) and repairs a user profile restored from another computer (e.g. ForensiT Transwiz) before the user's first sign-in. It unloads registry files the tool left loaded (temporary-profile error); rewrites the old computer's account SID to the user's in every registry key that still belongs to it (settings that won't save); clears migrated file and URL associations (flashing icons, defaults that won't stick); and renames `AppData\Local\Packages` if apps lack their per-app permissions, so Windows rebuilds it. The old SID is detected automatically; hive files, associations and Packages are kept as backups. Clears **all** associations, so only for a freshly restored profile. Needs UCPD stopped (`set-ucpd`) for 5 association keys. Ends with `RESULT unloaded= brokenkeys= fixedkeys= associations= assocfailed= packagesbad= packagesrenamed=`. |
| [`get-inventory.ps1`](scripts/get-inventory.ps1) | No | Configuration inventory as JSON: hardware (serial, CPU, RAM modules, disks), OS build, volumes, AD/Entra join, NICs and their power-saving state, BitLocker, AV/Defender/firewall, Windows Update (history, pending, policy), local users/admins/profiles, installed apps, remote-access services, power settings, Windows activation, printers, shared folders, saved Wi-Fi network names (never keys), listening TCP ports, and what starts automatically (Run keys of the machine and loaded users, startup folders, non-Microsoft scheduled tasks). Configuration only, so it can be committed and diffed; point-in-time health is `get-health`. Over SSH it prints JSON to stdout and writes nothing to disk. `-SkipUpdateSearch` skips the online pending-update search. |
| [`get-health.ps1`](scripts/get-health.ps1) | No | Health snapshot as JSON with **findings** ranked critical / warning / info: hardware errors (WHEA) by component and month over the whole retained System log (corrected memory errors = a failing DIMM), unexpected shutdowns, blue screens, disk and controller errors, application crashes and hangs, top errors and Defender detections in the last `-Days` (default 90), memory and commit use, CPU load, top processes, disk health and Windows reliability counters, SMART through `smartctl.exe` when found (`-SmartctlPath`, else `tools\smartctl.exe` next to the script, else a smartmontools install), free space, pending reboot, uptime, stability index, WMI repository consistency. At the machine it prints the findings. |
| [`get-app-usage.ps1`](scripts/get-app-usage.ps1) | No | When each installed application was last run, and by whom, as JSON: for retiring or rebuilding a machine. Reads Prefetch (any program, run count and last 8 runs), each user's UserAssist (programs a person started; a signed-out user's `NTUSER.DAT` is read from a temporary copy, never loaded in place) and BAM, plus services running from an app's folder. Maps them to the uninstall entries (hidden ones included) by install folder and keeps the raw `executions` list for apps that record none. Self-updating apps show prefetch runs nobody made, so `userAssist` is the "a person started it" signal. Changes nothing. |
| [`netdrop-diag.ps1`](scripts/netdrop-diag.ps1) | No | Network-loss evidence collector (adapters, power management, sleep/wake, connectivity, event logs) into a zip. Run while the failure is live, before rebooting. |

## Conventions (every script)

**Parameters and config.** Every per-site value is a parameter. Each script also takes `-Config <file.json>`. Precedence: **command-line argument > config file > built-in default**, decided with `$PSBoundParameters.ContainsKey()`. A config file is never required, so a script copied onto a USB stick still works on its own. Scripts read only the keys they know, so one client config file can serve every script. List-valued parameters accept either an array or a comma-separated string.

**Self-contained.** Each `.ps1` is a single file with no dot-sourced helpers, because it has to work when pasted or copied onto a machine with nothing else on it. The config-loading and self-elevation blocks are therefore repeated in each script. Keep them identical. The one exception is **data** a script needs that isn't per-site and changes independently of the code: it goes in a companion file `<script>.<name>.json` next to the script (so far only `install-apps.catalog.json`), read from the script's own folder. `win-run` uploads companion files with the script and removes them afterwards, and the download URLs serve them like scripts.

**ASCII only.** Windows PowerShell 5.1 reads a BOM-less UTF-8 `.ps1` as Windows-1252, so a single em dash breaks parsing of the whole file and nothing runs. `tools/check` and `win-run` both refuse non-ASCII files.

**5.1 syntax.** Target Windows PowerShell 5.1, not pwsh 7. No `? :`, `??` or `&&`/`||` pipeline chains.

**Self-elevating.** Run from a non-admin window, a script relaunches itself as Administrator (UAC) with all its arguments forwarded, and the elevated window stays open with `-NoExit`. Over SSH an admin-group session is already elevated, so it skips this step.

**No pause when unattended.** The closing "Press Enter" prompt is skipped with `-NoPause`, and automatically under SSH (`$env:SSH_CLIENT`) or when running as SYSTEM.

**Logging.** Transcripts and output go to `-LogDir` (default `C:\tmp`) as `<script>_<COMPUTERNAME>_<timestamp>`.

**Exit codes.** `0` OK, `1` a step failed, `2` usage or config error.

## Running a script

### At the machine (first contact: on-site, VNC, USB)

```powershell
powershell -ExecutionPolicy Bypass -File C:\tmp\enable-ssh-admin.ps1 -AllowFrom 192.0.2.10
```

`-ExecutionPolicy Bypass` gets past a restrictive machine policy for that one run. Click **Yes** at the UAC prompt.

### At the machine, from the USB kit

Right-click `enable-ssh.cmd` on the stick built by [`win-usb-kit`](#discovery-from-a-flash-drive), **Run as administrator**. It asks which address to allow SSH from (default: `AllowFrom` in the stick's `client.json`, Enter keeps it; `LocalSubnet` or `Any` when the final address isn't known yet, see `enable-ssh-admin` above), runs `enable-ssh-admin.ps1` from the stick with the stick's `client.json` (`AdminUser`, `PublicKeys`), and writes the log, host key fingerprint included, to `output\ssh\` on the stick. Nothing to download, and no network needed beyond what the OpenSSH feature install itself needs (Windows Update or a feature-on-demand source).

### At the machine, no USB stick (download in one line)

Open Command Prompt, PowerShell or Windows Terminal (admin not required; the script asks for elevation) and paste one line. It works in all three: it starts Windows PowerShell itself and contains no `$`, which the shells treat differently. Put the site's subnet router address after `-AllowFrom`:

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; md C:\tmp -ea 0 | Out-Null; irm https://bluegargoyle.com/ssh -OutFile C:\tmp\enable-ssh-admin.ps1; C:\tmp\enable-ssh-admin.ps1 -AllowFrom 192.0.2.10"
```

- `https://bluegargoyle.com/ssh` redirects to `enable-ssh-admin.ps1` at the **current release tag** on GitHub, never to `main`, so an unreleased edit can't reach a client machine.
- The TLS line is for older Windows 10 builds, where Windows PowerShell 5.1 still defaults to TLS 1.0 and GitHub refuses the connection.
- The file is saved before it runs (not `irm | iex`), so parameters, self-elevation and the transcript work as usual, and the file can be read first.
- Over SSH or in any other shell, `curl.exe -L -o C:\tmp\enable-ssh-admin.ps1 https://bluegargoyle.com/ssh` does the same download (type `curl.exe`; in Windows PowerShell 5.1 plain `curl` is an alias for `Invoke-WebRequest`).

The script is public. Nothing in it identifies a site: the only per-site value, `-AllowFrom`, goes on the command line you send the client.

### From the operator machine (once SSH works)

```bash
win-run [-c client.json] [--file | --as-task] <host> <script> [script args...]
```

- `<script>` is a name from `scripts/` (`.ps1` optional) or a path.
- `-c` uploads the config next to the script and passes `-Config`.
- `--as-task` runs it as a one-off SYSTEM scheduled task and polls until it finishes. Use it for anything that bounces the network adapter the SSH session uses: run directly, the session can die mid-run and leave the NIC disabled.
- `win-run` prints nothing until the script ends, and an `--as-task` run (Windows Update, a profile repair) can take many minutes. When driving it from an agent or another script, run it in the background or with a bound, and say up front roughly how long it may take; a silent foreground wait can hide a run that an EDR agent already killed (SentinelOne, 2026-10-26).
- **Not behind an EDR agent.** EDR products (seen with SentinelOne) flag a scheduled task created from a remote session and running as SYSTEM as lateral movement, and kill the whole session's process tree, `sshd` included. On EDR-protected machines run scripts directly (plain `win-run`), and give network-affecting scripts a staged mode that writes settings without dropping the link, then reboot. Plain `win-run` (read-only collectors, CIM queries) has not been flagged.
- `--file` launches the script with `powershell -File`, and does setup and cleanup with plain commands, so no `-EncodedCommand` is used at all. Use it on hosts whose AV kills encoded PowerShell. Seen with **Norton 360**: an encoded session that wraps a script block or starts system queries is killed silently, so `win-run` prints nothing and still exits 0. A bare one-line encoded command gets through, so a quick test can mislead. With `--file`, errors go to stderr instead of being merged into stdout.
- Uploads (the script, the config, and any `<script>.*.json` companion file next to the script) go to `C:\tmp\win-admin\` and are removed afterwards (`--keep` leaves them). The script's transcript and output stay in `C:\tmp`.

```bash
win-run pc01 netdrop-diag -DnsTestName example.com
win-run -c ~/src/<client>-infra/windows/client.json pc01 enable-ssh-admin
win-run --as-task pc01 disable-network-power-saving          # no EDR agent
win-run pc01 disable-network-power-saving -NoReload          # EDR agent present; reboot afterwards
win-run --file pc01 get-inventory > pc01.json                # AV kills encoded PowerShell (Norton)
win-run -c client.json pc01 install-apps                     # the client's standard apps (Apps key); plain SSH is fine
win-run pc01 install-updates -ScanOnly                       # what is pending (plain SSH is fine)
win-run --as-task --timeout 3600 pc01 install-updates        # one install cycle as SYSTEM; reboot if reboot=True, repeat
```

Put `bin/` on `PATH` (or symlink `bin/win-run` into `~/.local/bin`).

By default `win-run` sends every remote command as `powershell -EncodedCommand` (base64 UTF-16LE), because Windows command-line parsing strips nested quotes from a plain `ssh host '<powershell>'`. `--file` avoids that by keeping its command lines to single-quoted paths and arguments.

## Inventory

```bash
win-run pc01 get-inventory > inventory/raw/pc01.json        # in the client repo
win-inventory-render -c windows/client.json inventory/raw/*.json
```

The JSON is the record: commit it in the client repo so later runs can be compared, and paste the rendered table into the inventory doc. Fields the machine can't report (purchase date, the person using it, role) stay hand-maintained. `schema` is versioned (`win-admin/inventory/v1`); a breaking field change bumps it.

Notes on the data:
- Per-user applications come only from loaded registry hives (the profiles signed in at collection time). Machine-wide installs are complete.
- "Allow the computer to turn off this device" is read from two sources, `Get-NetAdapterPowerManagement` and `MSPower_DeviceEnable`. They can disagree (seen on Win11 26H2), and the renderer flags it when they do.
- USB Ethernet adapters report `Unsupported` from `Get-NetAdapterPowerManagement` and have no `MSPower_DeviceEnable` instance; that is treated as "no value", not a disagreement.
- BIOS placeholder strings ("Default string", "To be filled by O.E.M.") stay in the JSON but are hidden in the rendered table.

## Health

```bash
win-run pc01 get-health > pc01-health.json
python3 -c 'import json,sys; [print(f["severity"], f["message"]) for f in json.load(open(sys.argv[1]))["findings"]]' pc01-health.json
```

A snapshot, not a record to diff: processes, memory and event counts change every run. Keep it where the finding is written up, or not at all. Notes:
- The hardware-error history only goes back as far as the System log does (`eventLogCoverage`); on a busy machine that can be weeks. Firmware keeps its own log (Dell: the RMT event log in BIOS setup), which can hold errors Windows never logged.
- `UNEXPECTED_SHUTDOWNS` counts Kernel-Power 41 in the window, including any shutdown the operator caused by unplugging the machine; check the dates.
- Windows' reliability counters are often all zero or empty on SATA drives behind Intel RST (`busType` `RAID`); only smartctl gives real SMART data there.

## Discovery from a flash drive

For a first visit, before a machine has SSH (and to leave nothing behind on it): one launcher, `discovery.cmd`, runs `get-inventory`, `get-health` and `get-app-usage` from the stick and writes their JSON back to it. Read-only on the machine. A second launcher, `enable-ssh.cmd`, sets up SSH from the same stick (it changes the machine), see [At the machine, from the USB kit](#at-the-machine-from-the-usb-kit).

Build the stick on the Mac with one command, then pick the drive when asked:

```bash
~/src/win-admin/bin/win-usb-kit
```

It:
1. Lists external **FAT32/exFAT** drives only (backup disks and anything Windows can't read are listed as "not offered") and waits for one to be plugged in if there is none. `--volume /Volumes/<name>` picks one directly; for a drive that isn't FAT32/exFAT it offers to erase the whole drive as exFAT, after you type the volume's name.
2. Copies `usb/discovery.cmd` with the three collectors, and `usb/enable-ssh.cmd` with `enable-ssh-admin.ps1`, from the **newest release tag** (`git fetch`, then `git archive`; `--tag` for another), with CRLF line endings for the launchers. `--config ~/src/<client>-infra/windows/client.json` puts the client's config on the stick as `client.json` (for `enable-ssh.cmd`); without it, a `client.json` already on the stick is kept.
3. Gets `tools/smartctl.exe`: the latest smartmontools Windows installer from its GitHub release, GPG signature checked against the fingerprints pinned in the script (`SMT_KEYS`, from smartmontools.org's Download page), 64-bit `smartctl.exe` extracted with 7-Zip, cached in `~/Library/Caches/win-admin/smartmontools/<version>/`. 7-Zip and GnuPG are installed with Homebrew if missing. If any of that fails (no network, a release signed with a new key, no Homebrew), it says why and asks you to drag in an installer or `smartctl.exe` you downloaded yourself (an `.asc` next to an installer is checked); Enter skips smartctl. `--smartctl FILE` supplies one up front, `--no-smartctl` builds without it.
4. Writes everything to the root of the drive, plus `KIT-VERSION.txt` (release, commit, smartctl and config source, build date). An existing `output\` folder is never touched, so a stick with collected data can be rebuilt.
5. Checks every file on the drive against its source (SHA-256), removes macOS `._` files, and ejects.

The resulting drive:

```
discovery.cmd  get-inventory.ps1  get-health.ps1  get-app-usage.ps1
enable-ssh.cmd  enable-ssh-admin.ps1  client.json (with --config)  KIT-VERSION.txt
tools\smartctl.exe   (unless skipped)
output\              (collections; output\ssh\ holds enable-ssh logs)
```

When a smartmontools release is signed with a new key, `win-usb-kit` names the key; check its fingerprint on smartmontools.org's Download page and add it to `SMT_KEYS`. smartmontools is GPL; the binary is never committed here.

On each machine: right-click `discovery.cmd`, **Run as administrator**, wait 1-3 minutes. Output lands in `output\<COMPUTERNAME>_<timestamp>\` on the stick (`get-inventory.json`, `get-health.json`, `get-app-usage.json`), and the health findings are printed. When it says "Safe to eject", move on.

At home: render the inventory with `win-inventory-render` and commit it in the client repo like any SSH collection; read the health findings and app usage into the write-up.

If the antivirus blocks a script ("This script contains malicious content and has been blocked by your antivirus software"): that is AMSI, which `-ExecutionPolicy Bypass` does not get around. Seen with Bitdefender on `enable-ssh-admin.ps1` (a heuristic, `CMD:Heur...`). Add an exception for that one file in the AV (by its path on the stick: an exception for `C:\tmp\enable-ssh-admin.ps1` doesn't cover `D:\enable-ssh-admin.ps1`) and run again; for smartctl.exe (raw disk access sometimes trips "riskware" heuristics), an exception for `tools\smartctl.exe`. If Group Policy enforces an execution policy (`Get-ExecutionPolicy -List` shows MachinePolicy/UserPolicy), `-ExecutionPolicy Bypass` is ignored; that needs a policy exception from whoever runs the GPO.

## Client repos

A client repo does **not** copy the scripts. It holds:

```
<client>-infra/windows/
  client.json   # that client's values: AllowFrom (subnet router LAN IP), DnsTestName, SupportContact ...
  README.md     # how this client is reached (tailnet profile, subnet router), the win-run lines in use
```

Keys: see [`config/example.json`](config/example.json).

## Application catalog

[`scripts/install-apps.catalog.json`](scripts/install-apps.catalog.json) lists every application `install-apps` can install. Client configs only pick names from it (`"Apps": ["chrome", "firefox"]`); where an installer comes from and who must have signed it is decided here, in this reviewed public repo, never in a client file. For the same reason the script's `-Catalog` parameter (another catalog file) is not read from `-Config`.

Each entry, keyed by the name clients use:

| Field | Meaning |
|---|---|
| `Url` | The vendor's MSI over `https://` (a stable "latest" link) |
| `Signer` | The `O=` of the MSI's signing certificate. The install is refused unless the signature is Valid and names it |
| `Sha256` | For a vendor that doesn't sign its MSI (7-Zip): the exact file's SHA-256, so `Url` must point at one pinned version. The install is refused unless the download matches. Take it from a published checksum (e.g. the GitHub release asset's digest, `gh api repos/<owner>/<repo>/releases/tags/<tag>`) and confirm it against the file you downloaded |
| `MsiArgs` | Optional extra `msiexec` properties for that MSI, appended to `/i ... /qn /norestart`. Only for settings the vendor documents for silent installs, such as Zoom's update switches |
| `Match` | Wildcard on the `DisplayName` of the machine-wide uninstall entry, used to detect an existing install |
| `Name` | Display only |

Every entry needs `Signer`, `Sha256`, or both (both are checked when both are given). The script refuses to run (exit 2) if the catalog is missing, isn't valid JSON, has a different `Schema`, or has an entry without an `https://` Url, a Match, and a Signer or a 64-hex-digit Sha256.

**Pinned entries don't update.** Chrome and Firefox use vendor "latest" links and update themselves once installed. A `Sha256` entry is one fixed version: a new release means editing its `Url`, `Sha256` and `Name` and cutting a win-admin release, and machines that already have the application keep their version (install-apps skips installed applications; there is no upgrade mode yet). 7-Zip has no updater of its own.

Current catalog: `chrome`, `firefox` (signed, vendor "latest" links, update themselves); `7zip` (26.05, pinned by SHA-256; the 7-Zip MSI is not signed); `vlc` (3.0.24, signed by VideoLAN **and** pinned by SHA-256: VideoLAN has no stable "latest" MSI link, and the file comes from third-party mirrors). VLC only notifies about new versions; it doesn't install them unattended. `zoom` (signed by Zoom Communications, vendor "latest" link) needs `MsiArgs`: Zoom's MSI turns automatic updates **off** unless told otherwise (Zoom's Automatic Update Explainer), so the entry passes both the current switch (`ZConfig="AU2_EnableAutoUpdate=true"`) and the legacy one (`ZoomAutoUpdate="true"`). With only the AU2 switch the MSI still wrote `HKLM\SOFTWARE\Zoom\MSI\DisableUpdate = true`; with both it writes `false`. Not yet seen: an actual update arriving (needs Zoom's next release).

To add an application:

1. Download the vendor's MSI on a Windows machine and read its signer: `(Get-AuthenticodeSignature .\app.msi).SignerCertificate.Subject` (use the `O=` value). If the status is `NotSigned`, use a version-specific URL and `Sha256` instead (`(Get-FileHash .\app.msi).Hash`, confirmed against the vendor's published checksum).
   Download it **with PowerShell**, not only with curl: some download sites send a web page to a client they take for a browser (`get.videolan.org` gave PowerShell a 29 KB HTML page where curl got a redirect to the MSI). Check the size against the vendor's, and prefer the URL that returns the file (for VLC, `download.videolan.org/pub/videolan/...`). The script's signature/hash check refuses a web page anyway, but the entry has to point at a URL that works.
2. Install it once and read its `DisplayName` from `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` (or `WOW6432Node`) for `Match`.
3. Add the entry, run `tools/check`, test with `win-run <host> install-apps -Apps <name>`, commit, and release (the download URLs serve the catalog at the release tag).

At the machine without SSH, download both files into the same folder:

```
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol='Tls12'; md C:\tmp -ea 0 | Out-Null; irm https://bluegargoyle.com/win/install-apps.catalog.json -OutFile C:\tmp\install-apps.catalog.json; irm https://bluegargoyle.com/win/install-apps.ps1 -OutFile C:\tmp\install-apps.ps1; C:\tmp\install-apps.ps1 -Apps chrome,firefox"
```

## Adding a script

1. Start from an existing script: copy its `param()`, self-elevation, config-loading and `Finish` blocks unchanged.
2. Make every site-specific value a parameter with a neutral default (or none, and fail with exit 2 if it is required). Add its key to the config `foreach` list and to `config/example.json`.
3. Add `[switch]$NoPause`. `win-run` passes it automatically when the script declares it.
4. If the script reloads a network adapter, refuse to run under `$env:SSH_CLIENT` unless forced, and document `--as-task`.
5. Run `tools/check`, add a row to the Scripts table above, then commit.

## Releasing

The short download URLs point at a tag, so a script change reaches client machines only after a release.

1. Commit the change (after `tools/check`) and push.
2. Tag and push: `git tag -a v1.N -m "<what changed>" && git push origin v1.N`.
3. In the website repo (`bluegargoyle-website`), change the tag in each `win-admin` line of `_redirects` to `v1.N`, commit and push (Cloudflare Pages deploys on push).
4. Check: `curl -sIL https://bluegargoyle.com/ssh | grep -i '^location'` ends at the new tag's raw URL.

