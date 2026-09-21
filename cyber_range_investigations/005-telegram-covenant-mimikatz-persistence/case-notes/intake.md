# Case Notes — Intake

**Document Type:** Case Note  
**Case ID:** 005-telegram-covenant-mimikatz-persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Request Summary — range-supplied

The CyberRange briefing states that ThreatHunting flagged a suspicious binary in an
unusual path based on Sysmon logs and raised a possible insider incident, and that a
triage image was provided for analysis. The insider characterization originates in the
exercise material and is recorded here as framing, not as a finding.

**Primary Evidence Root:** `C:\Users\Administrator\Desktop\Start Here\Artifacts\`

## 2. Scope and Approach

**Primary goals**
- Footprint the system (OS build, hostname, timezone, last shutdown, network identifiers).
- Determine what the artifacts record about Telegram-named paths and their relationship
  to the suspicious executable.
- Identify the suspicious executable (disguised name, true identity, threat classification).
- Inventory persistence artifacts (services, scheduled tasks, new accounts) and
  distinguish creation or configuration records from evidence of execution.
- Determine evidence of credential access attempts and network share access.

**Primary artifact categories**
- Registry hives (SOFTWARE, SYSTEM) for OS and network configuration.
- User hive (NTUSER.DAT) for UserAssist and ShellBags (user activity and share access).
- NTFS artifacts ($MFT, $LogFile, $UsnJrnl/$J) for file create/rename history.
- Security Event Log (Security.evtx) for account creation and object access events.
- LNK files (Recent/Quick Launch/Taskbar pinned) for remote file/share access artifacts.
- A CyberRange-supplied Sysmon/Splunk view preserved as a screenshot; the underlying raw
  event log is not available.

## 3. Initial Findings

Timestamps are recorded on the basis their source attests. Values whose source states no
offset are marked accordingly and are not converted using the host timezone setting.

### Host Footprint
- **Windows Build:** 14393  
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` → `CurrentBuild`
- **Hostname:** MAGENTA  
  - `HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName`
- **Timezone (artifact):** Eastern Standard Time  
  - `HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation`
- **Last shutdown value:** 2021-07-30 15:25:38  
  - `HKLM\SYSTEM\ControlSet001\Control\Windows` → `ShutdownTime` (FILETIME)
  - Recorded at the precision the Registry Explorer Data Interpreter displays.

### Network Identifiers (defanged where applicable)
- **Host IP:** 10[.]10[.]5[.]113 (DHCP)  
- **DHCP server:** 10[.]10[.]5[.]1  
- **DNS server:** 10[.]10[.]4[.]159  
- **Last gateway MAC:** 16-1C-22-77-E5-9C  
- **Remote share host:** 10[.]10[.]5[.]86

### Supplied Network Telemetry
- Sysmon Event ID 3, Network Connect, for
  `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`
- `TimeCreated`: 2022-11-11 21:16:22.351523300 UTC (source field ends in `Z`); `UtcTime`: 2022-11-11 21:16:21.185
- Destination (defanged): 3[.]125[.]209[.]94 TCP port 80 (`DestinationPortName`: `http`),
  ec2-3-125-209-94[.]eu-central-1[.]compute[.]amazonaws[.]com
- Source (defanged): 10[.]10[.]5[.]113 port 65431, process ID 4328

### Telegram-Named NTFS Entries
- LSN 3980112160, 2022-11-11 21:54:56 UTC 0, Directory Creation, `Telegram Desktop`
- LSN 3980134702, 2022-11-11 21:54:57 UTC 0, File Creation, `Telegram.exe`
- LSN 3980703330, 2022-11-11 21:55:24 UTC 0, Directory Creation, `Telegram Desktop`

The view exposes leaf names only. The parent path is not available, so these entries
cannot be bound to the `Downloads\Telegram Desktop` path in the supplied telemetry. The
adjacent analyst transcription records LSN 3980134702 as creation of `Telegram Desktop`;
the view records `Telegram.exe`. The conflict is recorded, not resolved.

### Application Usage (UserAssist, offset unestablished)
- `...\AppData\Roaming\Telegram Desktop\Telegram.exe` — run count 4,
  last execution 11/11/2022 9:21:15 PM, focus time 383811 ms
- `...\Downloads\Telegram Desktop\Minecraft.exe` — run count 3,
  last execution 11/11/2022 9:23:13 PM, focus time 187452 ms
- `gkape.exe` and `kape.exe` — 11/11/2022 9:52:56 PM. Forensic-tool executions,
  separated from incident-behavior findings; the record does not identify the operator
  or bind them to the triage acquisition.

### Payload Identification
- `Minecraft.exe`, SHA-256
  b384fd495a751060f890fb785c68ed765d517e26b815c06655924348943ed2a5
- Identified as Covenant. Analyst-derived: the hash was submitted to VirusTotal and the
  identification recorded from returned community data. Not host telemetry, and not
  merged with the network event above.

### Account, Service and Task Artifacts
- **Account created:** `cpitter`  
  - Security.evtx **Event ID 4720** at 2022-11-11 21:23:51 UTC; the Event Log Explorer
    view displays a UTC indicator.
- **Service configuration:** `cleanup-schedule`  
  - `HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule`
  - `ImagePath`: `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`
  - `Start`: 2, `ObjectName`: LocalSystem
- **Scheduled task definition:** `\spawn`  
  - Registration date 2022-11-11 16:25:49, offset unestablished  
  - StartBoundary 2022-11-11 20:10:00, offset unestablished  
  - `Exec` action fields as the XML carries them: `Command` value ending in
    `\Downloads\Telegram`, `Arguments` value `Desktop\Minecraft.exe`

No surviving artifact shows subsequent use of the `cpitter` account, execution of the
`cleanup-schedule` service, or execution of the `\spawn` task.

### Masquerade / Credential Access / Share Access
- **Masquerade artifact:** `mimikatz.exe` created and later renamed to `svchost.exe`,
  correlated by a shared NTFS FileReferenceNumber. The NTFS export rows carry no offset
  column.
- **Credential file targeted:** `C:\Users\bfisher\Desktop\C-Levels\Credentials.txt`
  - Security.evtx **Event ID 4663**, subject `Account Name: Administrator`, process
    `dllhost.exe`, captured `Type: Audit Success`, offset unestablished
- **Remote share artifacts:**
  - ShellBags (NTUSER.DAT): remote network location involving 10[.]10[.]5[.]86
  - LNK / LECmd: file path `\\10[.]10[.]5[.]86\shared\lansweeper.ps1` (defanged UNC)

## 4. Evidence Model

Three artifact classes carry the literal full path `...\Downloads\Telegram Desktop\Minecraft.exe`:
the supplied Sysmon telemetry, the service `ImagePath`, and UserAssist. A fourth, the
scheduled-task `Exec` fields, associates the same material across two separate fields
without carrying the literal path. UserAssist additionally
records execution of `Minecraft.exe` itself.

None of those artifacts establishes that Telegram performed the download. The briefing
asserts the Telegram-download proposition and separately raises monitoring evasion as a
conditional hypothesis. Neither is adopted here.
Unresolved items are carried in the Limitations sections of the
[Timeline](../analysis/timeline-utc.md) and
[Final Report](../reports/final-report.md).
