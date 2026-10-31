# win-admin

Client-portable Windows administration toolkit: generic PowerShell scripts that run on the Windows machine, plus a Mac-side runner (`bin/win-run`) that ships and runs them over SSH.

Nothing here is specific to one site or client. Per-client values (subnet router address, DNS names, contact) live in each client's own repo as a JSON config file and are passed in at run time.

## Layout

| Path | What |
|---|---|
| `scripts/` | PowerShell scripts that run **on the Windows machine** (Windows PowerShell 5.1, Win10/11) |
| `bin/win-run` | Mac/Linux runner: upload a script (+ optional config) over SSH, run it, return its exit code, clean up |
| `bin/win-inventory-render` | Mac/Linux: render `get-inventory` JSON files as a Markdown table, one column per host (`-c client.json` for `AppsOfNote`, `--apps` for full app lists) |
| `config/example.json` | Every config key any script understands, with placeholder values |
| `tools/check` | Pre-commit check: ASCII-only + PowerShell parse check (`pwsh`) |

## Scripts

| Script | Changes config? | Purpose |
|---|---|---|
| [`enable-ssh-admin.ps1`](scripts/enable-ssh-admin.ps1) | **Yes** | One-time bootstrap of key-based OpenSSH admin access: operator account in Administrators, OpenSSH Server, PowerShell as default shell, `administrators_authorized_keys` with locked ACL, firewall rule on all profiles scoped to `-AllowFrom`, and an `sshd_config` block that turns off password/keyboard-interactive logins and allows only the admin user from `-AllowFrom` (`AllowUsers user@addr`; holds even where a third-party firewall such as Norton ignores the Windows rule). Validated with `sshd -t`, rolled back if invalid. Prints the host-key fingerprint. Requires `-AllowFrom`. |
| [`disable-network-power-saving.ps1`](scripts/disable-network-power-saving.ps1) | **Yes** | Turns off NIC/OS power saving that kills a wired link at idle (allow-turn-off, EEE/Green Ethernet, adapter and USB selective suspend, PCIe ASPM, Fast Startup). Reloads the adapters by default, so over SSH either pass `-NoReload` (stages the changes, then reboot) or use `win-run --as-task`. Behind an EDR agent use `-NoReload` (see below). |
| [`get-inventory.ps1`](scripts/get-inventory.ps1) | No | Configuration inventory as JSON: hardware (serial, CPU, RAM modules, disks), OS build, volumes, AD/Entra join, NICs and their power-saving state, BitLocker, AV/Defender/firewall, Windows Update (history, pending, policy), local users/admins/profiles, installed apps, remote-access services, power settings. Over SSH it prints JSON to stdout and writes nothing to disk. `-SkipUpdateSearch` skips the online pending-update search. |
| [`netdrop-diag.ps1`](scripts/netdrop-diag.ps1) | No | Network-loss evidence collector (adapters, power management, sleep/wake, connectivity, event logs) into a zip. Run while the failure is live, before rebooting. |

## Conventions (every script)

**Parameters and config.** Every per-site value is a parameter. Each script also takes `-Config <file.json>`. Precedence: **command-line argument > config file > built-in default**, decided with `$PSBoundParameters.ContainsKey()`. A config file is never required, so a script copied onto a USB stick still works on its own. Scripts read only the keys they know, so one client config file can serve every script. List-valued parameters accept either an array or a comma-separated string.

**Self-contained.** Each `.ps1` is a single file with no dot-sourced helpers, because it has to work when pasted or copied onto a machine with nothing else on it. The config-loading and self-elevation blocks are therefore repeated in each script. Keep them identical.

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

### From the operator machine (once SSH works)

```bash
win-run [-c client.json] [--file | --as-task] <host> <script> [script args...]
```

- `<script>` is a name from `scripts/` (`.ps1` optional) or a path.
- `-c` uploads the config next to the script and passes `-Config`.
- `--as-task` runs it as a one-off SYSTEM scheduled task and polls until it finishes. Use it for anything that bounces the network adapter the SSH session uses: run directly, the session can die mid-run and leave the NIC disabled.
- **Not behind an EDR agent.** EDR products (seen with SentinelOne) flag a scheduled task created from a remote session and running as SYSTEM as lateral movement, and kill the whole session's process tree, `sshd` included. On EDR-protected machines run scripts directly (plain `win-run`), and give network-affecting scripts a staged mode that writes settings without dropping the link, then reboot. Plain `win-run` (read-only collectors, CIM queries) has not been flagged.
- `--file` launches the script with `powershell -File`, and does setup and cleanup with plain commands, so no `-EncodedCommand` is used at all. Use it on hosts whose AV kills encoded PowerShell. Seen with **Norton 360**: an encoded session that wraps a script block or starts system queries is killed silently, so `win-run` prints nothing and still exits 0. A bare one-line encoded command gets through, so a quick test can mislead. With `--file`, errors go to stderr instead of being merged into stdout.
- Uploads go to `C:\tmp\win-admin\` and are removed afterwards (`--keep` leaves them). The script's transcript and output stay in `C:\tmp`.

```bash
win-run pc01 netdrop-diag -DnsTestName example.com
win-run -c ~/src/<client>-infra/windows/client.json pc01 enable-ssh-admin
win-run --as-task pc01 disable-network-power-saving          # no EDR agent
win-run pc01 disable-network-power-saving -NoReload          # EDR agent present; reboot afterwards
win-run --file pc01 get-inventory > pc01.json                # AV kills encoded PowerShell (Norton)
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

## Client repos

A client repo does **not** copy the scripts. It holds:

```
<client>-infra/windows/
  client.json   # that client's values: AllowFrom (subnet router LAN IP), DnsTestName, SupportContact ...
  README.md     # how this client is reached (tailnet profile, subnet router), the win-run lines in use
```

Keys: see [`config/example.json`](config/example.json).

## Adding a script

1. Start from an existing script: copy its `param()`, self-elevation, config-loading and `Finish` blocks unchanged.
2. Make every site-specific value a parameter with a neutral default (or none, and fail with exit 2 if it is required). Add its key to the config `foreach` list and to `config/example.json`.
3. Add `[switch]$NoPause`. `win-run` passes it automatically when the script declares it.
4. If the script reloads a network adapter, refuse to run under `$env:SSH_CLIENT` unless forced, and document `--as-task`.
5. Run `tools/check`, add a row to the Scripts table above, then commit.
