# Artifacts of Interest & IOCs — Case 004

**Case ID:** 004  
**Case Name:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Analyst:** Ryan Valera  
**Source Platform:** CyberDefenders CyberRange  
**Time Standard:** UTC (unless explicitly stated otherwise)

> **Defanging Notice:**  
> All URLs, IP addresses, and command strings in this document are **defanged**.  
> This file is intended for documentation and correlation only.

## Purpose of This Document

This document consolidates **high-confidence artifacts of interest** and **indicators of compromise (IOCs)** identified during Case 004.  
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

| Attribute | Value |
|---------|------|
| Application | Microsoft Word (Office) |
| Component | Equation Editor (`EQNEDT32.EXE`) |
| Office Version | `15.0.4420.1017` |
| CVE | `CVE-2017-11882` |
| Exploit Type | Remote Code Execution via crafted RTF |
| Macro Requirement | None |

## Execution & Staging Artifacts

### PowerShell Script (Primary Dropper)

| Attribute | Value |
|---------|------|
| Script Name | `msupdate.ps1` |
| Creation Time | `2025-05-23 11:15:43 UTC` |
| Location | `%TEMP%` (user context) |
| Execution Method | Hidden PowerShell via `cmd.exe` |
| Evidence Sources | NTFS $MFT, Sysmon EID 1 |

### Dropped Executable (Pattern-Based)

| Attribute | Value |
|---------|------|
| Naming Pattern | `msupdate-<random4>.exe` |
| Download Method | Encoded PowerShell command |
| Execution Method | `Start-Process` (defanged representation) |
| Evidence Source | Decoded registry persistence command |

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

| Attribute | Value |
|---------|------|
| Technique | Process spoofing |
| Spoofed Image | `notepad.exe` |
| Process ID | `13852` |
| Evidence Source | Sysmon EID 1 |

## Command & Discovery Artifacts

### Post-Exploitation Commands Observed

| Command | Purpose | Evidence |
|-------|---------|---------|
| `whoami` | User context discovery | Sysmon EID 1 |
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

## IOC Confidence Assessment

- **High confidence:**  
  - Phishing URL  
  - RTF document  
  - `msupdate.ps1`  
  - Registry Run key  
  - Startup LNK  
  - C2 IP and port 4444

- **Moderate confidence:**  
  - Secondary port 8080 activity  
  - Regsvr32 network activity context

## Status

Artifacts of interest are fully documented for the current scope of Case 004.  
This file will be updated if additional payloads, hashes, or infrastructure are identified.
