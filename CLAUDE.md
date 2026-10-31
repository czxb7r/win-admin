# CLAUDE.md -- win-admin

Client-portable Windows administration toolkit. Used for the operator's own Windows test machines and for Blue Gargoyle Consulting client sites. **No site or client assumptions belong in this repo**: client values go in the client repo's `windows/client.json`.

Read `README.md` first. It is authoritative for layout, script conventions, and how `win-run` works.

## Rules when editing

- Run `tools/check` before every commit. It enforces ASCII-only content (a single em dash breaks Windows PowerShell 5.1 parsing) and runs a parse check.
- Target Windows PowerShell 5.1 syntax, even though the local parse check uses pwsh 7.
- Each script stays a single self-contained file. The self-elevation and config-loading blocks are repeated on purpose; change all copies together.
- New per-site values become parameters plus a config key (and an entry in `config/example.json`), never hardcoded defaults.
- No client names, IPs, domains or people in scripts or docs. Use `192.0.2.x` / `example.com` placeholders.

## Driving a Windows host from a Claude session

- Use `bin/win-run` for scripts. For ad hoc commands, send PowerShell as `powershell -NoProfile -EncodedCommand <base64 UTF-16LE>`, because plain `ssh host '<cmd>'` loses nested quotes.
- Put `$ProgressPreference='SilentlyContinue'` first, or the output fills with `#< CLIXML` progress records.
- Never run anything that disables or re-enables the NIC directly over SSH. Use `win-run --as-task`, or a script's staged mode (`-NoReload`) plus a reboot. On machines with an EDR agent, don't use `--as-task`: a remote-created SYSTEM scheduled task is flagged as lateral movement and the session (including `sshd`) is killed.
- If `win-run` prints nothing and exits 0, suspect the AV killing `-EncodedCommand` PowerShell (seen with Norton 360) and retry with `win-run --file`.
- Before installing a feature on demand (OpenSSH, RSAT), check for a pending reboot or a busy TiWorker; either can stall the install for many minutes.
- A feature-on-demand install behind a third-party EDR agent (e.g. SentinelOne) can take 30 minutes. TiWorker can sit idle for 10+ minutes after the payload download and still finish, so an idle TiWorker alone does not mean the install is hung. Wait, and check `Get-WindowsCapability` before killing it.
- `SshRegister.exe` under `PFU\ScanSnap\Home` is the ScanSnap Home scanner app, not OpenSSH. Ignore it when diagnosing an SSH install.

## History

Origin: standardized remote admin access to Windows, decided 2026-10-20: SSH for CLI, VNC for GUI, WinRM optional). Scripts first built for a client engagement, then genericized here 2026-10-25.
