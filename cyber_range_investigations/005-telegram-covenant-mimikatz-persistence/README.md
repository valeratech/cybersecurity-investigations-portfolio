# Investigation Report

**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Case ID:** 005  
**Date Created:** 2026-02-18  
**Last Updated:** 2026-02-18  
**Author:** Ryan Valera  
**Time Standard:** UTC (unless CyberDefenders explicitly states otherwise)  
**Source Platform:** CyberDefenders (CyberRange)

## 1. Overview

### Objective
Investigate a triage image after ThreatHunting identified a suspicious binary path in Sysmon logs. Determine what occurred on the host, identify the suspicious binary, and reconstruct user activity around the time of the alert.

### Scenario Summary
A suspected insider incident was flagged during routine hunting. Analysis focused on artifacts in `Start Here\Artifacts` from a triage capture. Primary tasks included system footprinting, registry examination, NTFS journal review, Windows Event Log analysis, and shortcut/shell artifact review.

### Key Focus Areas
- Disk forensics (NTFS metadata/journals)
- Windows Registry analysis
- Windows Event Log analysis
- Persistence mechanisms (services, scheduled tasks)
- Lateral movement / network share access artifacts

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

## 4. Analysis & Findings

### 4.1 Initial Indicators
ThreatHunting flagged a suspicious binary path in Sysmon logs suggesting potential insider activity. Subsequent analysis identified Telegram usage to obtain a payload disguised as `Minecraft.exe`, later identified as a Covenant C2 artifact.

### 4.2 System Footprinting
- Windows build number: 14393  
  - Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion -> CurrentBuild
- Hostname: MAGENTA  
  - Registry: HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName
- Timezone setting (artifact): Eastern Standard Time  
  - Registry: HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation
- Last shutdown time: 2021-07-30 15:25 UTC  
  - Registry: HKLM\SYSTEM\ControlSet001\Control\Windows -> ShutdownTime

### 4.3 Network Context
- Host IP (DHCP): 10[.]10[.]5[.]113  
  - Registry: HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces\{GUID} -> DhcpIPAddress
- Last gateway MAC: 16-1C-22-77-E5-9C  
  - Registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList
- Network share host accessed: 10[.]10[.]5[.]86 (defanged)

### 4.4 Application Install / Usage
- Telegram Desktop install evidence (file creation): 2022-11-11 21:54:57 UTC
  - Source: NTFS/USN evidence from $LogFile / $J
- Telegram usage duration (UserAssist focus time): 383811 ms
  - Source: NTUSER.DAT (UserAssist)

### 4.5 Malware Identification
- Suspicious file: Minecraft.exe
- Identified framework: Covenant (C2)
- Known hash (SHA-256): b384fd495a751060f890fb785c68ed765d517e26b815c06655924348943ed2a5
- Threat intel source: VirusTotal (Community/YARA matches)

### 4.6 Persistence and Credential Access
- New user account created: cpitter
  - Evidence: Security.evtx Event ID 4720 at 2022-11-11 21:23:51 UTC
- Service created: cleanup-schedule
  - Registry: HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule
- Scheduled task created: \spawn
  - StartBoundary: 2022-11-11 20:10:00 UTC
  - Action path indicates execution of payload from Downloads path
- Masquerade activity:
  - svchost.exe executed from Downloads; original name determined as mimikatz.exe (rename evidence from NTFS logs)
- Unsuccessful access attempt observed against:
  - C:\Users\bfisher\Desktop\C-Levels\Credentials.txt
  - Evidence: Security.evtx Event ID 4663

### 4.7 Lateral Movement / Share Access
- Remote share accessed: \\10[.]10[.]5[.]86\shared\lansweeper.ps1
- Evidence sources: ShellBags (NTUSER.DAT) and LNK analysis (LECmd)

## 5. Current Status
- Baseline host footprinting complete
- Telegram install and minimal use supports “download-only” hypothesis
- Covenant identified and persistence artifacts confirmed (service + scheduled task)
- Credential access attempt and remote share activity identified
- Next step: expand timeline correlation across Security.evtx + NTFS events + LNK/ShellBags
