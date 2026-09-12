# Artifacts of Interest & IOCs — Case 004

**Document Type:** IOC Collection  
**Case ID:** 004-office-rtf-eqn-editor-powershell-c2  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

> **Defanging Notice:**  
> All URLs, IP addresses, and command strings in this document are **defanged**.  
> This file is intended for documentation and correlation only.

## Purpose of This Document

This document consolidates the **artifacts of interest** and **indicators of compromise (IOCs)** recorded during Case 004, each carrying the provenance of the record that establishes it.  
It acts as a single reference point for:
- Detection engineering
- Incident reporting
- Cross-case correlation
- Resume/portfolio defensibility

## Initial Access Indicators

### Phishing Infrastructure (DEFANGED)

| Type | Value |
|-----|------|
| URL | `hxxp[://]supportmlcrosoft[.]zapto[.]org[ / ]` |
| Delivery Method | Spoofed Microsoft 365-themed phishing portal |
| First Observed | `2025-05-23 10:52:59 UTC` |
| Source Evidence | Edge History (SQLite) |

## Delivered Payload

### Malicious Document

| Attribute | Value |
|---------|------|
| File Name | `Financial_Report.rtf` |
| File Type | Rich Text Format |
| Download Time | `2025-05-23 10:53:22 UTC` |
| Download Path | `C:\Users\harrisr\Downloads\` |
| Evidence Sources | Edge Downloads, NTFS $MFT |
| MOTW | Zone.Identifier present (internet origin) |

## Exploited Component

The Office version below is observed from the SOFTWARE hive. The Word and Equation Editor sequence is the CyberRange question premise, `CVE-2017-11882` is the answer the range recorded for it, and the exploit type is a reference description of that named CVE. No surviving process telemetry establishes the sequence on this host.

| Attribute | Value | Provenance |
|---------|------|------|
| Application | Microsoft Word (Office) | Range premise |
| Component | Equation Editor (`EQNEDT32.EXE`) | Range premise |
| Office Version | `15.0.4420.1017` | Observed |
| CVE | `CVE-2017-11882` | Range-recorded answer |
| Exploit Type | Remote Code Execution via crafted RTF | Reference description of the CVE |

## Execution Artifacts

### PowerShell Script

| Attribute | Value |
|---------|------|
| Script Name | `msupdate.ps1` |
| Creation Time | `2025-05-23 11:15:43 UTC` |
| Location | `%TEMP%` (user context) |
| Execution Method | Hidden PowerShell via `cmd.exe` |
| Evidence Sources | NTFS $MFT, Sysmon EID 1 |

### Executable Named in the Persistence Command

| Attribute | Value |
|---------|------|
| Remote filename | `payload.exe` |
| Local naming pattern | `msupdate-<random4>.exe` |
| Evidence Source | Decoded registry persistence command |
| Disk presence | Not established by the completed Q/A record |

## Persistence Indicators

### Registry-Based Persistence

| Attribute | Value |
|---------|------|
| Hive | `NTUSER.DAT` |
| Key Path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Value Name | `Microsoft Update Assistant` |
| Created Time | `2025-05-23 11:17:50 UTC` |
| Evidence Source | Sysmon EID 13 |

### Startup Folder Persistence

| Attribute | Value |
|---------|------|
| File Name | `WindowsUpdate.lnk` |
| Location | `...\Start Menu\Programs\Startup\` |
| Created Time | `2025-05-23 11:17:51 UTC` |
| Evidence Source | Sysmon EID 11 |

## Process & Evasion Artifacts

The CyberRange question set supplies the characterization that process spoofing was used to evade detection, and records `13852` as the spoofed-process PID. The surviving Sysmon EID 1 record independently shows PID `13852` (`notepad.exe`) as the parent of the `cmd.exe` process. That convergence does not establish that the parent was spoofed.

| Attribute | Value |
|---------|------|
| Range-characterized technique | Process spoofing, with evasion purpose also range-supplied |
| Range-recorded PID | `13852` |
| Observed image at that PID | `notepad.exe` |
| Observed relationship | Parent of the `cmd.exe` process, Sysmon EID 1 |

## Command & Discovery Artifacts

### Discovery Commands

| Command | Purpose | Evidence |
|-------|---------|---------|
| `whoami` | User context discovery | CyberRange question premise |
| `ipconfig /all` | Network configuration discovery | Sysmon EID 1 |
| `ping` | Connectivity testing | Sysmon EID 1 |
| `netstat` | Network connection discovery | Sysmon EID 1 |

## Network & C2 Indicators (DEFANGED)

| Attribute | Value |
|---------|------|
| External Host | `63[.]176[.]96[.]97` |
| Primary Port | `4444` |
| Secondary Port | `8080` |
| Protocol | TCP |
| Evidence Source | Sysmon EID 3 |

## Related MITRE ATT&CK Techniques

| Tactic | Technique |
|------|-----------|
| Initial Access | T1566 (Phishing) |
| Execution | T1203 (Exploitation for Client Execution) |
| Execution | T1059.001 (PowerShell) |
| Persistence | T1547.001 (Registry Run Keys) |
| Persistence | T1547.009 (Startup Folder) |
| Defense Evasion | T1036 (Masquerading) |
| Discovery | T1016, T1018 |
| Command and Control | T1571 (Non-Standard Port) |

## Indicator Provenance

This case classifies entries by evidentiary provenance rather than assigning
graded confidence labels.

- **Directly observed in preserved telemetry or disk artifacts:** phishing URL,
  `Financial_Report.rtf`, `msupdate.ps1`, the `Microsoft Update Assistant` Run
  key value, `WindowsUpdate.lnk`, the external host, and both observed ports
  `4444` and `8080`
- **Recorded by the CyberRange as an answer or premise:** `CVE-2017-11882`,
  the Word/Equation Editor sequence, the process-spoofing characterization,
  and `whoami`
- **Named in a preserved artifact rather than observed directly:**
  `payload.exe` and the `msupdate-<random4>.exe` naming pattern, both read from
  the decoded Run-key command

## Status

Artifacts of interest are fully documented for the current scope of Case 004.  
