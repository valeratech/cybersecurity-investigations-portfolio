# Analysis Tools and Methods – TeamCity APT Ransomware Investigation

**Document Type:** Reference

## Overview

This document outlines the tools, platforms, queries, and methodologies used during the investigation. It serves as a reference for how analysis was conducted and how findings were derived.

## Platforms and Data Sources

### Elastic Stack (Primary Analysis Platform)
- Centralized log analysis across all hosts
- Enabled correlation between Sysmon, PowerShell, Security, and network logs
- Used KQL (Kibana Query Language) for querying and filtering data

### Sysmon (Microsoft-Windows-Sysmon)
- Event ID 1: Process Creation
- Event ID 3: Network Connections
- Event ID 7: Module Load
- Event ID 10: Process Access (LSASS targeting)
- Event ID 11: File Creation

### Windows Event Logs
- Security Log (Event ID 4688, 4698)
- Task Scheduler (Event ID 106, 200, 201)
- MSSQL Logs (Event ID 18456, 15457)

### PowerShell Logging
- Event ID 4104 (Script Block Logging)
- Used to extract and decode attacker commands
- Key for identifying encoded payloads and malicious scripts

## Analytical Techniques

### KQL Querying

Used to filter and pivot across datasets for detection and correlation.

#### Example: Suspicious PowerShell Execution
`event.code:4104 AND message: (*downloadstring* OR *Invoke-Expression* OR *-EncodedCommand*)`

#### Example: Malware File Creation
`event.code:11 AND file.name:*.*.lsoc`

#### Example: Remote Execution via WMIC
`process.name:"wmic.exe" AND process.command_line:*process call create*`

## Decoding and Deobfuscation
### Base64 Decoding
Used to decode encoded PowerShell commands
Revealed:
- Malware download URLs
- C2 configuration
- Persistence mechanisms

### Command Analysis
Interpreted command-line activity from process logs
Identified LOLBins such as:
- `wmic`
- `rundll32`
- `cmd.exe`

## Threat Hunting Methodology
Indicator-Based Hunting
Pivoted from known IOCs:
- Attacker IP: `3[.]90[.]168[.]151`
- Host: `10[.]10[.]3[.]4`

Behavior-Based Detection
Focused on:
- Encoded PowerShell execution
- Defender modification commands
- Lateral movement patterns
- Scheduled task creation

## Timeline Correlation
Cross-referenced events across:
- Sysmon
- PowerShell logs
- Security logs
Reconstructed full attack lifecycle

## MITRE ATT&CK Mapping
- T1562.001 – Impair Defenses
- T1620 – Reflective Code Loading
- T1105 – Ingress Tool Transfer
- T1047 – Windows Management Instrumentation
- T1053 – Scheduled Task/Job
- T1003 – Credential Dumping

## Notes
- All analysis conducted using read-only data within Elastic
- No modification of original evidence
- All timestamps normalized to UTC
- All indicators defanged for safe documentation
