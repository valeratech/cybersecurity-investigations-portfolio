# Tools Usage Documentation – TeamCity APT Ransomware Investigation

**Document Type:** Evidence Metadata

## Overview

This document provides a detailed record of how each tool, platform, and data source was utilized during the investigation. It ensures transparency, reproducibility, and traceability of all analytical actions performed.

## Elastic Stack (SIEM Platform)

### Purpose
Primary platform for log aggregation, querying, and correlation across all compromised hosts.

### Usage
- Queried multi-source logs including Sysmon, PowerShell, Security, and MSSQL logs
- Performed correlation across hosts using IP addresses and process relationships
- Filtered events using KQL to identify attacker behavior patterns

### Key Capabilities Used
- Cross-index correlation
- Time-based filtering (UTC normalization)
- Field-based pivoting (IP, hostname, process, command-line)
- Event aggregation for anomaly detection

## Sysmon

### Purpose
Provided detailed endpoint telemetry for process execution, file activity, and network connections.

### Event IDs Used
- Event ID 1: Process Creation
- Event ID 3: Network Connection
- Event ID 7: Module Load
- Event ID 10: Process Access (LSASS targeting)
- Event ID 11: File Creation

### Usage
- Identified malicious process execution chains
- Tracked file creation related to ransomware and payload delivery
- Observed module loads associated with in-memory execution techniques

## Windows Event Logs

### Security Log

#### Event IDs Used
- 4688: Process Creation
- 4698: Scheduled Task Creation

#### Usage
- Validated process execution context and parent-child relationships
- Confirmed persistence mechanisms via scheduled task creation

### Task Scheduler Logs

#### Event IDs Used
- 106: Task Created
- 200 / 201: Task Execution

#### Usage
- Identified malicious scheduled tasks on DC01 and IT01
- Confirmed persistence and execution timing

## PowerShell Logging

### Purpose
Captured attacker command execution via script block logging.

### Event ID Used
- 4104: Script Block Logging

### Usage
- Identified encoded PowerShell commands
- Extracted and decoded Base64 payloads
- Revealed:
  - Malware download activity
  - Defender modification commands
  - Credential dumping techniques
  - Data exfiltration logic

## MSSQL Logs

### Purpose
Tracked authentication attempts and configuration changes on SQL Server.

### Event IDs Used
- 18456: Failed Login Attempts
- 15457: Configuration Changes

### Usage
- Identified brute-force attack (2062 attempts)
- Confirmed enabling of `xp_cmdshell`
- Correlated attacker activity post-compromise

## Reverse DNS Lookup

### Purpose
Resolve attacker IP address to associated domain.

### Usage
- IP: `3[.]90[.]168[.]151`
- Result:
  - `ec2-3-90-168-151.compute-1.amazonaws[.]com`

### Finding
- Attacker leveraged cloud-based infrastructure (AWS)

## Base64 Decoding

### Purpose
Decode obfuscated PowerShell commands used by the attacker.

### Usage
- Decoded `-EncodedCommand` payloads
- Extracted:
  - Download URLs
  - File paths
  - C2 configuration
  - Persistence commands

## MITRE ATT&CK Framework

### Purpose
Map observed attacker behavior to standardized TTPs.

### Techniques Identified
- T1562.001 – Impair Defenses
- T1620 – Reflective Code Loading
- T1105 – Ingress Tool Transfer
- T1047 – Windows Management Instrumentation
- T1053 – Scheduled Task/Job
- T1003 – Credential Dumping

## Notes

- All tools were used in a read-only investigative capacity
- No evidence was modified during analysis
- All timestamps were normalized to UTC
- All outputs were defanged for safe documentation
