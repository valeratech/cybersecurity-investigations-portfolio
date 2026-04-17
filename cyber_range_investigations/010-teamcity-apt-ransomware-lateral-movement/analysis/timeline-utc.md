# Timeline – TeamCity APT Ransomware Investigation

**Document Type:** Analysis

## Overview

This timeline reconstructs attacker activity across the CyberRange environment. All timestamps are normalized to UTC.

## Timeline of Events

| Timestamp (UTC)        | Host        | Event Description |
|-----------------------|------------|------------------|
| 2024-08-19 12:58:19   | JB01       | Ransom note file activity observed (`un-lock your files[.]html`) |
| 2024-08-20 03:55:13   | JB01       | Additional ransom note creation activity detected |
| 2024-08-20 04:00:00   | JB01       | Initial access via TeamCity exploitation (CVE-2024-27198) |
| 2024-08-20 04:05:00   | JB01       | PowerShell execution begins; malware download initiated |
| 2024-08-20 04:06:00   | JB01       | Binary saved to `C:\TeamCity\jre\bin\java64.exe` |
| 2024-08-20 04:07:00   | JB01       | Windows Defender disabled via `Set-MpPreference` |
| 2024-08-20 04:08:00   | JB01       | Defender exclusions added: `C:\TeamCity`, `C:\Windows` |
| 2024-08-20 04:09:00   | JB01       | Firewall rule created allowing inbound traffic on port `8080` |
| 2024-08-20 04:10:00   | JB01       | Command and control (C2) tunnel established |
| 2024-08-20 04:15:00   | JB01       | Reconnaissance commands executed (`wmic`, PowerView) |
| 2024-08-20 04:21:08   | SQL Server | Brute-force attack begins against MSSQL (Event ID 18456) |
| 2024-08-20 04:25:00   | SQL Server | Successful authentication to MSSQL server |
| 2024-08-20 04:26:00   | SQL Server | `xp_cmdshell` enabled |
| 2024-08-20 04:27:00   | SQL Server | Malware downloaded and executed via PowerShell |
| 2024-08-20 04:30:00   | SQL Server | winPEAS executed for privilege escalation |
| 2024-08-20 04:35:00   | SQL Server | Credential dumping initiated using EDR bypass tool |
| 2024-08-20 04:40:00   | SQL Server | Dump file created (`MpCmdRun-*.dmp`) |
| 2024-08-20 04:45:00   | SQL Server | Registry modifications for credential harvesting |
| 2024-08-20 05:00:00   | SQL Server | Lateral movement initiated using `wmic` |
| 2024-08-20 05:10:00   | FS01       | Beacon deployed (`AddressResourcesSpec.dll`) |
| 2024-08-20 05:15:00   | IT01       | Remote execution via `rundll32` |
| 2024-08-20 05:30:00   | DC01       | Scheduled tasks created for persistence |
| 2024-08-20 05:45:00   | JB01       | Data prepared for exfiltration using steganography |
| 2024-08-20 05:50:00   | JB01       | Files embedded into `jvpd2px2at1.bmp` |
| 2024-08-20 06:35:58   | Multiple   | Ransomware encryption begins (`.lsoc` extension observed) |
| 2024-08-20 06:40:42   | Multiple   | Peak encryption activity across systems |
| 2024-08-20 06:36:04   | Multiple   | Ransom note deployment begins |
| 2024-08-20 06:45:51   | Multiple   | Ransom note deployment completed |
| 2024-08-20 06:46:00   | Multiple   | Shadow copies deleted using `vssadmin.exe Delete Shadows /All /Quiet` |

## Summary

- Initial access originated from exploitation of a TeamCity server in the DMZ.
- The attacker rapidly established persistence, disabled defenses, and deployed malware.
- Lateral movement expanded compromise across SQL Server, Domain Controller, File Server, and IT workstation.
- Credential harvesting and reconnaissance enabled full domain compromise.
- Data was staged and exfiltrated prior to ransomware execution.
- Ransomware deployment caused widespread encryption and operational disruption.
