# Investigation Report

**Document Type:** Case Overview  
**Case Title:** Disk Forensics — Telegram, Covenant, mimikatz masquerade, and persistence artifacts  
**Case ID:** 005-telegram-covenant-mimikatz-persistence  
**Documentation Started:** 2026-02-18  
**Documentation Last Updated:** 2026-02-18  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Case Contents

### Analysis

- [Detection Engineering Notes](analysis/detection-engineering-notes.md)
- [Hunt Queries](analysis/hunt-queries.md)
- [MITRE ATT&CK Mapping](analysis/mitre-attack-mapping.md)
- [Timeline](analysis/timeline-utc.md)
- [Tools and Commands](analysis/tools-and-commands.md)

### Case Notes

- [Intake](case-notes/intake.md)

### Evidence Metadata

- [Evidence Log](evidence-metadata/evidence-log.md)

### Diagrams

- [Incident Flow](diagrams/incident-flow.md)

### Reports

- [Final Report](reports/final-report.md)

### Supporting Directories

Evidence-handling notes for artifacts excluded from version control: [scripts](scripts/README.md), [pcaps](pcaps/README.md).

## 1. Overview

### Objective
Investigate a triage image after ThreatHunting identified a suspicious binary path in
Sysmon logs. Determine what the artifacts record, identify the suspicious binary, and
reconstruct user activity around the time of the alert.

### Scenario Summary — range-supplied
The CyberRange briefing describes a suspected insider incident flagged during routine
hunting and states that Telegram was used to download an executable. It further raises,
conditionally, that the brief Telegram usage might indicate download-only use and an
attempt to evade network monitoring. The first is a range-supplied assertion; the second
is a range-supplied hypothesis. Both originate in the exercise material, are retained
here as attributed framing, and are not treated as findings.

Analysis focused on artifacts in `Start Here\Artifacts` from a triage capture. Primary
tasks included system footprinting, registry examination, NTFS journal review, Windows
Event Log analysis, and shortcut/shell artifact review.

### Key Focus Areas
- Disk forensics (NTFS metadata/journals)
- Windows Registry analysis
- Windows Event Log analysis
- Persistence artifacts (services, scheduled tasks)
- Network share access artifacts

### Time Basis
Timestamps are reported on the basis each source attests. Values whose source states no
offset are marked accordingly and are not converted using the host timezone setting.
The [Timeline](analysis/timeline-utc.md) and [Final Report](reports/final-report.md)
carry the full time-basis breakdown and the unresolved items.

## 2. Environment & Tools Used

### Environment Description
- Hostname: MAGENTA
- Observed domain: polo[.]shirts[.]corp
- Windows Build: 14393
- System timezone setting (artifact): Eastern Standard Time
- Host IP (defanged): 10[.]10[.]5[.]113

### Tools & Applications
- Registry Explorer (load hives from `C:\Windows\System32\config`)
- NTFS Log Tracker ($LogFile, $MFT, $UsnJrnl/$J)
- UserAssist Forensic Tool (NTUSER.DAT)
- ShellBags Explorer (NTUSER.DAT)
- Event Log Explorer (Security.evtx)
- LECmd (LNK parsing) + Timeline Explorer (review output)
- Visual Studio Code (output searching)
- VirusTotal (hash reputation / community intel)
- Windows CMD and PowerShell

## 3. Evidence Collected

### Evidence Artifacts (Triage)
- Registry hives: SOFTWARE, SYSTEM (`...\C\Windows\System32\config\`)
- User hive: `...\C\Users\Administrator\NTUSER.DAT`
- Windows Security log: `Security.evtx`
- NTFS metadata: `$MFT`, `$LogFile`, `$Extend\$J`
- Scheduled task file: `...\C\Windows\System32\Tasks\spawn`
- LNK sources:
  - `...\Microsoft\Internet Explorer\Quick Launch\`
  - `...\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\`
  - `...\Microsoft\Windows\Recent\`

### Supplied Evidence
- A CyberRange-supplied Sysmon/Splunk view, preserved as a screenshot. The underlying
  raw Sysmon event log is not available.

## 4. Analysis & Findings

### 4.1 Initial Indicators
ThreatHunting flagged a suspicious binary path in Sysmon logs. The supplied Sysmon view
records an outbound TCP connection to port 80 by `Minecraft.exe` from a path containing
`Telegram Desktop`. The characterization of this as insider activity, and the
proposition that Telegram performed the download, are range-supplied.

### 4.2 System Footprinting
- Windows build number: 14393  
  - Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion -> CurrentBuild
- Hostname: MAGENTA  
  - Registry: HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName
- Timezone setting (artifact): Eastern Standard Time  
  - Registry: HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation
- Last shutdown value: 2021-07-30 15:25:38  
  - Registry: HKLM\SYSTEM\ControlSet001\Control\Windows -> ShutdownTime
  - Reported as the Registry Explorer Data Interpreter displays it, at the precision
    the tool shows.

### 4.3 Network Context
- Host IP (DHCP): 10[.]10[.]5[.]113  
  - Registry: HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{GUID} -> DhcpIPAddress
- Last gateway MAC: 16-1C-22-77-E5-9C  
  - Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList
- Network share host recorded in ShellBags: 10[.]10[.]5[.]86 (defanged)

### 4.4 Supplied Network Telemetry
- Sysmon Event ID 3, Network Connect, for
  `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`
- `TimeCreated`: 2022-11-11 21:16:22.351523300 UTC; the source field ends in `Z`
- `UtcTime`: 2022-11-11 21:16:21.185
- Destination (defanged): 3[.]125[.]209[.]94 TCP port 80 (`DestinationPortName`: `http`)
- Destination hostname (defanged): ec2-3-125-209-94[.]eu-central-1[.]compute[.]amazonaws[.]com
- Source (defanged): 10[.]10[.]5[.]113 port 65431, process ID 4328
- Provenance: supplied screenshot. The event establishes an outbound TCP connection to
  port 80, labelled `http` by `DestinationPortName` - a port-to-service label, not protocol
  inspection. It does not establish that HTTP was used or what content traversed the
  connection.

### 4.5 Telegram-Named NTFS Entries
The surviving NTFS Log Tracker view records three entries under an `EventTime (UTC 0)`
column:

| LSN | EventTime (UTC 0) | Event | Name |
|---|---|---|---|
| 3980112160 | 2022-11-11 21:54:56 | Directory Creation | Telegram Desktop |
| 3980134702 | 2022-11-11 21:54:57 | File Creation | Telegram.exe |
| 3980703330 | 2022-11-11 21:55:24 | Directory Creation | Telegram Desktop |

The view exposes leaf names only; the parent path of these entries is not available.
They therefore cannot be bound to the `Downloads\Telegram Desktop` path recorded in the
supplied Sysmon telemetry. The adjacent analyst transcription records LSN 3980134702 as
creation of `Telegram Desktop`; the view records it as creation of `Telegram.exe`. That
conflict is recorded, not resolved.

### 4.6 Application Usage
UserAssist records, with timezone/offset unestablished:

| Program | Run count | Last execution | Focus time |
|---|---|---|---|
| `...\AppData\Roaming\Telegram Desktop\Telegram.exe` | 4 | 11/11/2022 9:21:15 PM | 383811 ms |
| `...\Downloads\Telegram Desktop\Minecraft.exe` | 3 | 11/11/2022 9:23:13 PM | 187452 ms |

The same artifact also records `gkape.exe` and `kape.exe` executions at
11/11/2022 9:52:56 PM. These are forensic-tool executions and are separated from the
incident-behavior findings; the surviving record does not identify the operator or bind
them to the triage acquisition.

### 4.7 Payload Identification
- Suspicious file: Minecraft.exe
- Hash (SHA-256): b384fd495a751060f890fb785c68ed765d517e26b815c06655924348943ed2a5
- Identified framework: Covenant
- Provenance: analyst-derived. The hash was submitted to VirusTotal and a Covenant
  identification recorded from the returned community data. This is enrichment of a
  file hash, not host telemetry, and is not merged with the network event in 4.4.

### 4.8 Account, Service and Task Artifacts
- Account created: cpitter
  - Evidence: Security.evtx Event ID 4720 at 2022-11-11 21:23:51 UTC
  - The Event Log Explorer view displays a UTC indicator.
- Service configuration: cleanup-schedule
  - Registry: HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule
  - `ImagePath`: `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`
  - `Start`: 2, `ObjectName`: LocalSystem
- Scheduled task definition: \spawn
  - Registration date: 2022-11-11 16:25:49, offset unestablished
  - StartBoundary: 2022-11-11 20:10:00, offset unestablished
  - `Exec` action fields as the XML carries them: `Command` value ending in
    `\Downloads\Telegram`, `Arguments` value `Desktop\Minecraft.exe`
- Masquerade artifact:
  - `mimikatz.exe` created and later renamed to `svchost.exe`, correlated by a shared
    NTFS FileReferenceNumber. The NTFS export rows carry no offset column.
- Access attempt recorded against:
  - C:\Users\bfisher\Desktop\C-Levels\Credentials.txt
  - Evidence: Security.evtx Event ID 4663, subject `Account Name: Administrator`,
    process `dllhost.exe`, captured `Type: Audit Success`, offset unestablished

No surviving artifact shows subsequent use of the `cpitter` account, execution of the
`cleanup-schedule` service, or execution of the `\spawn` task.

### 4.9 Network Share Artifacts
- Two artifact classes record different things:
  - ShellBags (NTUSER.DAT): remote network location involving host 10[.]10[.]5[.]86
  - LNK analysis (LECmd): the file path `\\10[.]10[.]5[.]86\shared\lansweeper.ps1`
- The range question characterizes `lansweeper.ps1` as the file the attacker accessed on
  the share. That characterization is range-supplied; the artifacts record a network
  location and a file path, not an access event.

## 5. Current Status

- Baseline host footprinting complete
- Three artifact classes place `Minecraft.exe` in a `Downloads\Telegram Desktop` path:
  supplied Sysmon telemetry, the service `ImagePath`, and UserAssist. A fourth, the
  scheduled-task `Exec` fields, associates the same material across two fields.
- None of those artifacts establishes that Telegram performed the download. That
  proposition is range-supplied.
- Covenant identification is analyst-derived from a file hash.
- Account, service and task artifacts are creation or configuration records. No
  surviving artifact shows subsequent use of the `cpitter` account, execution of the
  `cleanup-schedule` service, or execution of the `\spawn` task.
- UserAssist records execution of `Minecraft.exe` itself, with offset unestablished.
- Unresolved items are carried in the Limitations sections of the
  [Timeline](analysis/timeline-utc.md) and [Final Report](reports/final-report.md).

## 6. Case Status

**Status:** Complete  
