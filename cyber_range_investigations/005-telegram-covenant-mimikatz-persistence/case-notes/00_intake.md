# Case Notes — Intake

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Source Platform:** CyberDefenders (CyberRange)  
**Time Standard:** UTC (unless CyberDefenders explicitly states otherwise)  
**Primary Evidence Root:** `C:\Users\Administrator\Desktop\Start Here\Artifacts\`

## 1. Request Summary

ThreatHunting flagged a suspicious binary in an unusual path based on Sysmon logs and raised a possible insider incident. A triage image was provided for analysis to determine what occurred on the host and what actions were executed around the alert timeframe.

## 2. Scope and Approach

**Primary goals**
- Footprint the system (OS build, hostname, timezone, last shutdown, network identifiers).
- Determine Telegram install and usage context (potential monitoring bypass).
- Identify the suspicious executable (disguised name, true identity, threat classification).
- Validate persistence mechanisms (services, scheduled tasks, new accounts).
- Determine evidence of credential access attempts and network share access.

**Primary artifact categories**
- Registry hives (SOFTWARE, SYSTEM) for OS and network configuration.
- User hive (NTUSER.DAT) for UserAssist and ShellBags (user activity and share access).
- NTFS artifacts ($MFT, $LogFile, $UsnJrnl/$J) for file create/rename history.
- Security Event Log (Security.evtx) for account creation and object access events.
- LNK files (Recent/Quick Launch/Taskbar pinned) for remote file/share access artifacts.

## 3. Initial High-Confidence Findings (from provided analysis)

### Host Footprint
- **Windows Build:** 14393  
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` → `CurrentBuild`
- **Hostname:** MAGENTA  
  - `HKLM\SYSTEM\ControlSet001\Control\ComputerName\ComputerName`
- **Timezone (artifact):** Eastern Standard Time  
  - `HKLM\SYSTEM\ControlSet001\Control\TimeZoneInformation`
- **Last shutdown time:** 2021-07-30 15:25 UTC  
  - `HKLM\SYSTEM\ControlSet001\Control\Windows` → `ShutdownTime` (FILETIME)

### Network Identifiers (defanged where applicable)
- **Host IP:** 10[.]10[.]5[.]113 (DHCP)  
- **DHCP server:** 10[.]10[.]5[.]1  
- **DNS server:** 10[.]10[.]4[.]159  
- **Last gateway MAC:** 16-1C-22-77-E5-9C  
- **Remote share host:** 10[.]10[.]5[.]86

### Telegram + Malware Context
- **Telegram install evidence:** 2022-11-11 21:54:57 UTC (Telegram Desktop directory creation)
- **Telegram usage (UserAssist Focus Time):** 383811 ms
- **Downloaded/masqueraded payload:** `Minecraft.exe` identified as **Covenant** (C2 framework)
  - **SHA-256:** b384fd495a751060f890fb785c68ed765d517e26b815c06655924348943ed2a5

### Persistence + Identity Actions
- **New user created:** `cpitter`  
  - Security.evtx **Event ID 4720** at 2022-11-11 21:23:51 UTC
- **Service created:** `cleanup-schedule`  
  - `HKLM\SYSTEM\ControlSet001\Services\cleanup-schedule`
- **Scheduled task:** `\spawn`  
  - First scheduled run: 2022-11-11 20:10:00 UTC  
  - Task action references execution of payload from the Downloads path.

### Masquerade / Credential Access / Lateral Movement
- **Masquerade evidence:** `svchost.exe` executed from Downloads; original name determined as `mimikatz.exe`
  - NTFS log evidence shows rename activity tied to the same File Reference Number.
- **Credential file targeted:** `C:\Users\bfisher\Desktop\C-Levels\Credentials.txt`
  - Security.evtx **Event ID 4663**
- **Remote share file accessed:** `\\10[.]10[.]5[.]86\shared\lansweeper.ps1` (defanged UNC)

## 4. Working Hypothesis

Telegram Desktop was installed shortly before the alert and used very briefly, consistent with a “download-only” intent to bypass enterprise monitoring controls. The payload was disguised as `Minecraft.exe` but aligns with Covenant tooling, and additional actions indicate persistence (service + scheduled task), credential-access activity (mimikatz masquerade), and attempted access to sensitive credential material and a remote share.
