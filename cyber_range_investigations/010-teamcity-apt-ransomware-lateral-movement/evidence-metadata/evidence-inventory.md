# Evidence Inventory – TeamCity APT Ransomware Investigation

**Document Type:** Evidence Metadata

## Overview

This document tracks all evidence sources utilized during the investigation. All artifacts are preserved in their original state and were analyzed through centralized logging platforms.

## Evidence Inventory

| Evidence ID | Artifact Type | Source System | Description | Collection Method | Integrity / Hash | Notes |
|-------------|--------------|--------------|-------------|-------------------|------------------|-------|
| EVT-001 | Log Data | Elastic Stack | Pre-parsed centralized logs from all hosts | Provided CyberRange dataset | N/A | Primary investigation data source |
| EVT-002 | Sysmon Logs | Multiple Hosts | Process creation, network connections, file creation, module loads | Elastic ingestion | N/A | Event IDs 1, 3, 7, 10, 11 used extensively |
| EVT-003 | PowerShell Logs | JB01, SQL Server, DC01 | Script block logging (Event ID 4104) for attacker commands | Elastic ingestion | N/A | Used for decoding attacker activity |
| EVT-004 | Windows Security Logs | Multiple Hosts | Authentication, process execution, scheduled task creation | Elastic ingestion | N/A | Event IDs 4688, 4698 analyzed |
| EVT-005 | Task Scheduler Logs | DC01, IT01 | Scheduled task creation and execution | Elastic ingestion | N/A | Event IDs 106, 200, 201 |
| EVT-006 | MSSQL Logs | SQL Server (10[.]10[.]0[.]6) | Authentication attempts and configuration changes | Elastic ingestion | N/A | Event ID 18456 (failed logins), 15457 (config changes) |
| EVT-007 | Network Logs | JB01 (10[.]10[.]3[.]4) | HTTP requests, external communication, malware downloads | Elastic ingestion | N/A | Used to identify attacker infrastructure |
| EVT-008 | Reverse DNS Lookup | External | Resolution of attacker IP to FQDN | External lookup tool | N/A | Identified AWS infrastructure |
| EVT-009 | Decoded Payloads | Multiple Hosts | Base64-decoded PowerShell commands | Manual decoding | N/A | Revealed C2, persistence, and credential access activity |

## Evidence Handling Notes

- All data was analyzed in-place via the Elastic SIEM environment.
- No original evidence files were modified during analysis.
- All timestamps were normalized to UTC.
- Evidence sources were correlated across multiple hosts to reconstruct attacker activity.

## Chain of Custody Considerations

- Data provided by CyberRange platform (trusted training environment)
- No external evidence ingestion beyond provided dataset
- Integrity maintained through read-only analysis within SIEM environment
