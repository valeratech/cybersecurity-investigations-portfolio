# Unified Timeline (UTC)

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders (CyberRange)

## Timeline Construction Method

This timeline consolidates timestamps from:

- Registry artifacts (SYSTEM / SOFTWARE hives)
- NTFS metadata ($LogFile, $MFT, $UsnJrnl/$J)
- Windows Security Event Logs (Security.evtx)
- Scheduled Task XML
- UserAssist (NTUSER.DAT)
- LNK analysis (LECmd output)

All timestamps are normalized to UTC.

## Chronological Event Timeline

### 2021-07-30 15:25:00 UTC
**Event:** Last recorded system shutdown  
**Source:** Registry  
**Path:** HKLM\SYSTEM\ControlSet001\Control\Windows → ShutdownTime  
**Interpretation:** Establishes historical system activity baseline.

## 2022-11-11 Activity Cluster (Primary Incident Window)

### 2022-11-11 20:10:00 UTC
**Event:** Scheduled task `\spawn` first scheduled to run  
**Source:** Task XML (`System32\Tasks\spawn`)  
**Field:** `<StartBoundary>`  
**Interpretation:** Indicates persistence configured prior to or during active exploitation window.

### 2022-11-11 21:23:51 UTC
**Event:** New local user account created  
**Account:** cpitter  
**Event ID:** 4720  
**Source:** Security.evtx  
**Interpretation:** Privilege persistence attempt via new account creation.

### 2022-11-11 21:44:29 UTC
**Event:** `mimikatz.exe` created in Downloads directory  
**Source:** NTFS ($LogFile / $J)  
**Evidence Type:** File_Created  
**Interpretation:** Credential harvesting tool staged locally.

### 2022-11-11 21:47:23 UTC
**Event:** Data modification to `mimikatz.exe`  
**Source:** NTFS journal  
**Interpretation:** File possibly written or modified before execution.

### 2022-11-11 21:48:08 UTC
**Event:** Rename operation  
`mimikatz.exe` → `svchost.exe`  
**Source:** NTFS journal (File_Renamed_Old / File_Renamed_New)  
**Correlation Key:** FileReferenceNumber match  
**Interpretation:** Masquerading to evade detection.

### 2022-11-11 21:54:57 UTC
**Event:** Telegram Desktop directory created  
**Source:** NTFS ($LogFile / $UsnJrnl)  
**Interpretation:** Telegram installed shortly before or during malicious staging.

### 2022-11-11 (UserAssist Evidence)
**Event:** Telegram usage recorded  
**Focus Time:** 383811 milliseconds  
**Source:** NTUSER.DAT (UserAssist)  
**Interpretation:** Very limited usage consistent with “download-only” behavior.

### 2022-11-11 19:55:51 UTC
**Event:** Object access attempt  
**Target File:** `C:\Users\bfisher\Desktop\C-Levels\Credentials.txt`  
**Event ID:** 4663  
**Process:** `dllhost.exe`  
**Source:** Security.evtx  
**Interpretation:** Attempt to access credential storage file.

### 2022-11-11 (ShellBags / LNK Evidence)
**Event:** Access to remote share  
**UNC Path (defanged):** \\10[.]10[.]5[.]86\shared\lansweeper.ps1  
**Source:** LNK metadata + ShellBags  
**Interpretation:** Lateral exploration of network share for credential or reconnaissance script.

## Supporting Context

### Host Network Configuration
- Host IP: 10[.]10[.]5[.]113
- Remote Share Host: 10[.]10[.]5[.]86
- DHCP Server: 10[.]10[.]5[.]1
- DNS Server: 10[.]10[.]4[.]159
- Gateway MAC: 16-1C-22-77-E5-9C

## Incident Flow Summary (High-Level)

1. Telegram installed.
2. Suspicious payload downloaded (disguised as Minecraft.exe).
3. Payload identified as Covenant framework.
4. Credential tool (mimikatz) staged and renamed to svchost.exe.
5. New user account created.
6. Persistence mechanisms established:
   - Scheduled Task (`\spawn`)
   - Service (`cleanup-schedule`)
7. Credential file access attempted.
8. Remote network share accessed (`lansweeper.ps1`).

## Analytical Notes

- The short Telegram usage window supports controlled acquisition of tooling.
- NTFS rename evidence strongly supports intentional masquerade.
- User creation and service/task persistence indicate deliberate foothold establishment.
- Access to credential-related file and remote share indicates post-exploitation behavior.

## Next Step

- Correlate service creation timestamp with NTFS and Security logs.
- Validate ImagePath of `cleanup-schedule`.
- Confirm execution evidence for renamed `svchost.exe`.
- Map behaviors to MITRE ATT&CK techniques.
