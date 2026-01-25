# Sysmon Filters & Event Analysis — Case 004

**Case ID:** 004  
**Case Name:** Office RTF (Equation Editor) → PowerShell Persistence → C2  
**Analyst:** Ryan Valera  
**Source Platform:** CyberDefenders CyberRange  
**Time Standard:** UTC (unless explicitly stated otherwise)

## Purpose of This File

This document records the **Sysmon event IDs, filters, and search logic** used to identify:
- Malicious execution
- Post-exploitation discovery activity
- Persistence mechanisms
- Command-and-control communications

This file supports **reproducibility** and explains how key events were isolated from Sysmon telemetry.

## Sysmon Event IDs Used

| Event ID | Description | Investigation Use |
|--------|-------------|-------------------|
| 1 | Process Create | Execution chain, discovery commands, spoofed processes |
| 3 | Network Connection | C2 identification and port usage |
| 11 | File Create | Startup persistence artifacts |
| 13 | Registry Value Set | Registry Run key persistence |

## Event ID 1 — Process Creation

### Filters Applied
- Image contains:
  - `powershell`
  - `cmd.exe`
  - `notepad.exe`
  - `regsvr32.exe`
- CommandLine contains:
  - `msupdate.ps1`
  - `whoami`
  - `ipconfig`
  - `ping`
  - `netstat`
- User:
  - `WIN-DMZ0\harrisr`

### Key Findings
- Hidden PowerShell execution launched via `cmd.exe`
- Script executed:
  - `C:\Users\harrisr\AppData\Local\Temp\msupdate.ps1`
- Process spoofing observed:
  - `notepad.exe` referenced as a masqueraded process
  - Associated Process ID: `13852`

## Event ID 3 — Network Connection

### Filters Applied
- Destination IP (defanged):
  - `63[.]176[.]96[.]97`
- Destination Port:
  - `4444`
  - `8080`
- Image:
  - `powershell.exe`
  - `regsvr32.exe`

### Key Findings
- Outbound TCP connection to non-standard port `4444` established by PowerShell
- Secondary outbound connection to port `8080` observed via `regsvr32.exe`
- Network activity occurred shortly after payload execution

## Event ID 11 — File Creation

### Filters Applied
- TargetFilename contains:
  - `Startup`
  - `.lnk`

### Key Findings
- Startup persistence file created:
  - `WindowsUpdate.lnk`
- Location:
`C:\Users\harrisr\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`

- Timestamp: `2025-05-23 11:17:51 UTC`

## Event ID 13 — Registry Value Set

### Filters Applied
- TargetObject contains:
- `Software\Microsoft\Windows\CurrentVersion\Run`

### Key Findings
- Registry Run key persistence established
- Value name:
- `Microsoft Update Assistant`
- Associated executable:
- Hidden PowerShell invocation (encoded)
- Timestamp: `2025-05-23 11:17:50 UTC`

## Limitations & Notes

- Sysmon event descriptions were not rendered in the CyberRange viewer
- Analysis relied on:
- Parsed event fields
- Correlation with NTFS $MFT and browser artifacts
- No packet capture was available; network findings are host-based

## Summary

Sysmon telemetry provided high-confidence evidence of:
- Exploitation-driven execution
- Process masquerading
- Multiple discovery commands
- Redundant persistence mechanisms
- Command-and-control communications over non-standard ports

These findings were corroborated with disk and registry artifacts.
