# Investigation Timeline — Case 004

**Case ID:** 004  
**Case Name:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Analyst:** Ryan Valera  
**Source Platform:** CyberDefenders CyberRange  
**Time Standard:** UTC (unless explicitly stated otherwise)

## Timeline Methodology

This timeline consolidates **browser artifacts, NTFS $MFT data, registry activity, and Sysmon telemetry** into a single chronological view.

- All timestamps are recorded in **UTC**
- Events are ordered by first-observed evidence
- Each entry references the **primary artifact source**

## Consolidated Timeline (UTC)

| Timestamp (UTC) | Event Description | Evidence Source | Artifact / Path |
|-----------------|------------------|-----------------|-----------------|
| 2025-05-23 10:52:59 | User accessed phishing portal (defanged) | Edge History (SQLite) | `Edge\User Data\Default` |
| 2025-05-23 10:53:22 | Malicious RTF downloaded | Edge Downloads | `...\Downloads\Financial_Report.rtf` |
| 2025-05-23 10:53:22 | File created on disk | NTFS $MFT | `...\Users\harrisr\Downloads\Financial_Report.rtf` |
| 2025-05-23 10:53:22 | Zone.Identifier ADS created (internet origin) | NTFS ADS | `Financial_Report.rtf:Zone.Identifier` |
| 2025-05-23 10:53:35 | Recent file shortcut created | NTFS $MFT | `...\Windows\Recent\Financial_Report.lnk` |
| 2025-05-23 10:54:02 | Outbound connection to external host on non-standard port | Sysmon EID 3 | `PowerShell → 63[.]176[.]96[.]97:4444` |
| 2025-05-23 10:59:18 | Network discovery command executed (`netstat`) | Sysmon EID 1 | `NETSTAT.EXE` |
| 2025-05-23 10:59:33 | Connectivity test executed (`ping`) | Sysmon EID 1 | `PING.EXE 8.8.8.8` |
| 2025-05-23 10:59:48 | System network configuration discovery (`ipconfig /all`) | Sysmon EID 1 | `IPCONFIG.EXE` |
| 2025-05-23 11:15:43 | Malicious PowerShell script created | NTFS $MFT | `%TEMP%\msupdate.ps1` |
| 2025-05-23 11:17:44 | Hidden PowerShell execution via cmd.exe | Sysmon EID 1 | `cmd.exe → powershell (hidden)` |
| 2025-05-23 11:17:50 | Registry Run key persistence established | Sysmon EID 13 | `HKCU\...\Run\Microsoft Update Assistant` |
| 2025-05-23 11:17:51 | Startup folder persistence created | Sysmon EID 11 | `Startup\WindowsUpdate.lnk` |
| 2025-05-23 10:53:53 | Secondary outbound connection observed (defanged) | Sysmon EID 3 | `regsvr32.exe → 63[.]176[.]96[.]97:8080` |

## Timeline Observations

- Initial access and payload delivery occurred within **23 seconds**
- External network communication was observed **before** overt discovery commands
- Persistence mechanisms were created **within ~2 minutes** of script creation
- Multiple discovery commands indicate **post-exploitation situational awareness**
- Redundant persistence suggests intent for **long-term access**

## Notes

- Timeline entries are correlated across **browser artifacts, NTFS metadata, and Sysmon telemetry**
- Some Sysmon event descriptions were unavailable in the viewer; conclusions rely on parsed event fields
- All IOCs referenced here are defanged
