# Evidence Log

**Document Type:** Evidence Inventory  
**Case ID:** 005-telegram-covenant-mimikatz-persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Evidence Overview

**Evidence Type:** Triage image artifact set  

This investigation is based on a structured artifact directory provided within the
CyberDefenders lab:

`C:\Users\Administrator\Desktop\Start Here\Artifacts\`

The evidence consists of extracted system artifacts from a Windows host. No full disk
image or memory image was provided; analysis relies on triage artifacts.

One further item is supplied rather than recovered: a CyberRange-supplied Sysmon/Splunk
view preserved as a screenshot. It is inventoried in Section 9.

## 2. Registry Hives

### SYSTEM Hive
Location:
`...\C\Windows\System32\config\SYSTEM`

Purpose:
- Hostname identification
- Timezone configuration
- Last shutdown value (ShutdownTime)
- Network configuration (TCP/IP interfaces)
- Service configuration

Key Registry Paths Used:
- `HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName`
- `HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation`
- `HKLM\SYSTEM\ControlSet001\Control\Windows`
- `HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces`
- `HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule`

### SOFTWARE Hive
Location:
`...\C\Windows\System32\config\SOFTWARE`

Purpose:
- Windows build/version identification
- NetworkList historical connections
- NetworkCards mapping

Key Registry Paths Used:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards`

### User Hive (NTUSER.DAT)
Location:
`...\C\Users\Administrator\NTUSER.DAT`

Purpose:
- UserAssist (application execution, run count and focus time)
- ShellBags (network share access artifacts)

## 3. Windows Event Logs

### Security.evtx
Location:
`...\C\Windows\System32\winevt\Logs\Security.evtx`

Relevant Event IDs:
- **4720** – User account creation (new account: cpitter)
- **4663** – Object access attempt (Credentials.txt)

## 4. NTFS Artifacts

### $MFT
Location:
`...\C\$MFT`

Purpose:
- File metadata
- File reference number correlation

### $LogFile
Location:
`...\C\$LogFile`

Purpose:
- File and directory creation activity (Telegram-named entries)
- File rename activity (mimikatz.exe → svchost.exe)

### $UsnJrnl ($Extend\$J)
Location:
`...\C\$Extend\$J`

Purpose:
- File system journal tracking
- Rename correlation via FileReferenceNumber

## 5. Scheduled Tasks

Location:
`...\C\Windows\System32\Tasks\spawn`

Purpose:
- Persistence artifact inventory
- Task definition values, recorded as the XML carries them:
  - `<Date>` (registration): 2022-11-11 16:25:49, no `Z` or numeric offset stated
  - `<StartBoundary>`: 2022-11-11 20:10:00, no `Z` or numeric offset stated
  - `Exec` action: `Command` value ending in `\Downloads\Telegram`,
    `Arguments` value `Desktop\Minecraft.exe`

## 6. LNK Artifact Sources

The following directories were used as inputs for LECmd analysis:

- `...\Microsoft\Internet Explorer\Quick Launch\`
- `...\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\`
- `...\Microsoft\Windows\Recent\`

Purpose:
- Evidence of file access
- Evidence of remote share file access
- Working directory correlation

## 7. Identified Artifact

File Name:
`Minecraft.exe`

Identified As:
Covenant

SHA-256:
b384fd495a751060f890fb785c68ed765d517e26b815c06655924348943ed2a5

Source:
VirusTotal reputation and YARA match (THOR APT Scanner rule). Analyst-derived
enrichment of a file hash, not host telemetry.

## 8. Network Identifiers (Defanged)

- Host IP: 10[.]10[.]5[.]113  
- Remote share host: 10[.]10[.]5[.]86  
- DHCP server: 10[.]10[.]5[.]1  
- DNS server: 10[.]10[.]4[.]159  
- Sysmon-recorded destination: 3[.]125[.]209[.]94 TCP port 80 (`DestinationPortName`: `http`)  
- Sysmon-recorded destination hostname: ec2-3-125-209-94[.]eu-central-1[.]compute[.]amazonaws[.]com

## 9. Supplied Evidence

**Item:** CyberRange-supplied Sysmon/Splunk view, preserved as a screenshot in the
exercise material.

Recorded content:
- Event ID 3, Network Connect
- Image: `C:\Users\Administrator\Downloads\Telegram Desktop\Minecraft.exe`
- `TimeCreated` (System): 2022-11-11 21:16:22.351523300 UTC; the source field ends in `Z`
- `UtcTime` (EventData): 2022-11-11 21:16:21.185
- Source: 10[.]10[.]5[.]113 port 65431, process ID 4328

Handling: treated as surviving telemetry evidence with supplied provenance stated at
every point of use. The underlying raw Sysmon event log is not available, so this item
cannot be re-queried, filtered, or corroborated against an original log.

## 10. Evidence Handling Notes

- Timestamps are recorded on the basis each source attests. Values whose source states
  no offset are marked as such and are not converted using the host timezone setting.
  The [Timeline](../analysis/timeline-utc.md) carries the full breakdown.
- Indicators have been defanged for public repository safety.
- No live system interaction occurred; analysis performed on static artifacts.
- No evidence files are redistributed in this repository (metadata only).

---
