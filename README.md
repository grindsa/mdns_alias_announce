# mDNS Alias Announcer (PowerShell)

SPDX-License-Identifier: GPL-3.0-only

This project provides a custom mDNS responder/announcer for Windows using PowerShell.

It publishes custom `.local` hostnames from a text file and responds to mDNS queries over UDP 5353, including:

- A (IPv4) records
- AAAA (IPv6) records when a usable IPv6 is available
- Unicast responses when requested by the mDNS QU bit
- Multicast periodic announcements

## Features

- Loads aliases from a file (ignores empty lines and comments beginning with `#`)
- Normalizes names to `.local`
- Auto-detects the primary local IPv4 interface and pins multicast traffic to it
- Optional IPv6 support for AAAA answers, including IPv6 mDNS transport on the same interface
- Verbose query/response diagnostics (`-Verbose`)
- Optional transcript logging (`-LogToFile`)
- Startup network profile self-check (warns for Public profile)

## Requirements

- Windows PowerShell 5.1+ (or PowerShell 7+ on Windows)
- Administrative rights recommended (binding/inspection/firewall/task setup)
- Local network allows mDNS multicast (`224.0.0.251:5353`)

## Files

- `mdns_alias_announce.ps1`: main script
- `aliases.txt`: alias input file (you can also pass a custom path with `-FilePath`)

## Alias File Format

Example `aliases.txt`:

```text
# Comments are allowed
TestBox
WIN-ANY-NAME.domain.local
domain.local
```

Notes:

- `TestBox` becomes `TestBox.local`
- Name matching is case-insensitive

## Run Manually

Basic run:

```powershell
powershell -ExecutionPolicy Bypass -File C:\programdata\mdns_alias_announce\mdns_alias_announce.ps1 -FilePath C:\programdata\mdns_alias_announce\aliases.txt
```

With verbose and logging:

```powershell
powershell -ExecutionPolicy Bypass -File C:\programdata\mdns_alias_announce\mdns_alias_announce.ps1 -FilePath C:\programdata\mdns_alias_announce\aliases.txt -Verbose -LogToFile -LogFilePath C:\programdata\mdns_alias_announce\mdns_alias_announce.log
```

## Parameters

- `-FilePath <string>`: alias input file path
- `-IntervalSeconds <int>`: periodic announcement interval in seconds (range: `1..86400`, default: `30`)
- `-LogToFile`: enable transcript logging
- `-LogFilePath <string>`: transcript destination path (default: `mdns_alias_announce.log` next to script)

## Create Firewall Rules (PowerShell)

Run in an elevated PowerShell session:

```powershell
# Inbound mDNS to local UDP 5353
New-NetFirewallRule `
  -DisplayName "mDNS Alias Responder Inbound UDP 5353" `
  -Direction Inbound `
  -Action Allow `
  -Protocol UDP `
  -LocalPort 5353 `
  -Profile Private,Domain `
  -RemoteAddress LocalSubnet

# Outbound mDNS multicast to UDP 5353
New-NetFirewallRule `
  -DisplayName "mDNS Alias Responder Outbound UDP 5353" `
  -Direction Outbound `
  -Action Allow `
  -Protocol UDP `
  -RemotePort 5353 `
  -Profile Private,Domain `
  -RemoteAddress 224.0.0.251
```

Verify rules:

```powershell
Get-NetFirewallRule -DisplayName "mDNS Alias Responder *" | Format-Table -Auto Name, DisplayName, Enabled, Direction, Action
```

Remove rules:

```powershell
Remove-NetFirewallRule -DisplayName "mDNS Alias Responder Inbound UDP 5353"
Remove-NetFirewallRule -DisplayName "mDNS Alias Responder Outbound UDP 5353"
```

## Run at Boot (Scheduled Task)

Run in an elevated PowerShell session:

```powershell
$ScriptPath = "C:\programdata\mdns_alias_announce\mdns_alias_announce.ps1"
$AliasFile  = "C:\programdata\mdns_alias_announce\aliases.txt"
$LogFile    = "C:\programdata\mdns_alias_announce\mdns_alias_announce.log"

$Action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -FilePath `"$AliasFile`" -IntervalSeconds 30 -LogToFile -LogFilePath `"$LogFile`""

$Trigger = New-ScheduledTaskTrigger -AtStartup

$Principal = New-ScheduledTaskPrincipal `
  -UserId "SYSTEM" `
  -LogonType ServiceAccount `
  -RunLevel Highest

$Settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -RestartCount 999 `
  -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask `
  -TaskName "mDNS Alias Announcer" `
  -Action $Action `
  -Trigger $Trigger `
  -Principal $Principal `
  -Settings $Settings `
  -Description "Starts custom PowerShell mDNS alias responder at boot"
```

Start now without reboot:

```powershell
Start-ScheduledTask -TaskName "mDNS Alias Announcer"
```

Check status:

```powershell
Get-ScheduledTask -TaskName "mDNS Alias Announcer" | Get-ScheduledTaskInfo
```

Update task (replace existing):

```powershell
Unregister-ScheduledTask -TaskName "mDNS Alias Announcer" -Confirm:$false
# Then run the Register-ScheduledTask block again
```

## Startup Checklist

Use this quick checklist after install or reboot:

1. Confirm `aliases.txt` exists and contains at least one alias.
2. Confirm UDP 5353 firewall rules are present for the network profile in use.
3. Confirm the host is on a trusted LAN segment (same L2 domain / VLAN as clients).
4. Start the script or scheduled task and watch startup output for selected interface/IP.
5. Run one client-side lookup test (A/AAAA) before considering setup complete.

Quick checks on Windows:

```powershell
Get-Content C:\programdata\mdns_alias_announce\aliases.txt
Get-NetFirewallRule -DisplayName "mDNS Alias Responder *"
Get-ScheduledTask -TaskName "mDNS Alias Announcer" | Get-ScheduledTaskInfo
```

## Known Limitations

- This script is focused on host A/AAAA answers only (no PTR/SRV/TXT service discovery records).
- IPv6 transport requires usable IPv6 on the selected interface; link-local-only (`fe80::/10`) addresses are ignored.
- Multi-homed hosts can still have edge cases if the default route does not match the LAN where clients query.
- This implementation does not perform mDNS conflict probing/defense logic before announcing names.
- Network equipment with client isolation, strict multicast filtering, or cross-VLAN boundaries may block discovery.

## Verification Workflow

Use this sequence to validate behavior end-to-end.

1. Start responder with verbose logging:

```powershell
powershell -ExecutionPolicy Bypass -File C:\programdata\mdns_alias_announce\mdns_alias_announce.ps1 -FilePath C:\programdata\mdns_alias_announce\aliases.txt -Verbose
```

2. Query from a client (macOS example):

```bash
dns-sd -G v4v6 testbox.local
```

3. Capture multicast traffic if results are inconsistent:

```bash
sudo tcpdump -ni en0 udp port 5353
```

Expected result:

- Verbose logs show `match=True` for the queried name.
- Client receives A response (and AAAA when usable IPv6 is configured).

## Troubleshooting

1. Script runs, but macOS cannot resolve names:
- Confirm firewall rules exist for UDP 5353
- Ensure both devices are in the same L2 broadcast domain / VLAN
- Verify no AP/client isolation is enabled on Wi-Fi

2. Verbose logs show queries but `match=False`:
- Check alias spelling in `aliases.txt`
- Ensure queried name exists as `.local`

3. Only AAAA queries seen from client:
- Script will answer AAAA only when a usable non-link-local IPv6 exists on selected interface
- Otherwise it still answers A queries when requested

4. Confirm mDNS traffic on macOS:

```bash
dns-sd -G v4v6 testbox.local
sudo tcpdump -ni en0 udp port 5353
```

## License

See `LICENSE`.
