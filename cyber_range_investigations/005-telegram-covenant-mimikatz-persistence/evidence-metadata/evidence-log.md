# Evidence Log

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Source Platform:** CyberDefenders (CyberRange)  
**Time Standard:** UTC  
**Evidence Type:** Triage image artifact set  

## 1. Evidence Overview

This investigation is based on a structured artifact directory provided within the CyberDefenders lab:

`C:\Users\Administrator\Desktop\Start Here\Artifacts\`

The evidence consists of extracted system artifacts from a Windows host. No full disk image or memory image was provided; analysis relies on triage artifacts.

## 2. Registry Hives

### SYSTEM Hive
Location:
`...\C\Windows\System32\config\SYSTEM`

Purpose:
- Hostname identification
- Timezone configuration
- Last shutdown time (ShutdownTime)
- Network configuration (TCP/IP interfaces)
- Services (persistence validation)

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
- UserAssist (application execution + focus time)
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
- File creation activity (Telegram Desktop)
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
- Persistence validation
- Execution timing (StartBoundary: 2022-11-11 20:10:00 UTC)

## 6. LNK Artifact Sources

The following directories were used as inputs for LECmd analysis:

- `...\Microsoft\Internet Explorer\Quick Launch\`
- `...\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\`
- `...\Microsoft\Windows\Recent\`

Purpose:
- Evidence of file execution
- Evidence of remote share file access
- Working directory correlation

## 7. Identified Malicious Artifact

File Name:
`Minecraft.exe`

Identified As:
Covenant (C2 framework)

SHA-256:
b384fd495a751060f890fb785c68ed765d517e26b815c06655924348943ed2a5

Source:
VirusTotal reputation + YARA match (THOR APT Scanner rule)

## 8. Network Identifiers (Defanged)

- Host IP: 10[.]10[.]5[.]113  
- Remote share host: 10[.]10[.]5[.]86  
- DHCP server: 10[.]10[.]5[.]1  
- DNS server: 10[.]10[.]4[.]159  

## 9. Evidence Handling Notes

- All timestamps recorded in UTC.
- Indicators have been defanged for public repository safety.
- No live system interaction occurred; analysis performed on static artifacts.
- No evidence files are redistributed in this repository (metadata only).

---
