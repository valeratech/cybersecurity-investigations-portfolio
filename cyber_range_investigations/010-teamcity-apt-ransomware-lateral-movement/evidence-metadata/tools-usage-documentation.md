# Tools Usage Documentation – TeamCity APT Ransomware Investigation

**Document Type:** Reference  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Overview

This document records how each tool and data source appears in the case record. Queries are reproduced in [Analysis Tools and Methods](../case-notes/analysis-tools-and-methods.md).

## Elastic (Kibana)

### Purpose

The provided Elastic instance holds pre-parsed logs from the compromised systems.

### Usage

- KQL queries in Discover, recorded in the notes for most questions
- Field statistics (top values and counts) for fields such as `file.extension`, `process.command_line` and `http.request.referrer`
- The time picker, to narrow a search to a time window
- Host filters on `host.ip` and `host.name`
- Displayed times are UTC: in two Sysmon events the displayed `@timestamp` equals the event's `UtcTime`

## Sysmon

- Event ID 1 (process creation): command lines on JB01 (Q9) and the command that reached FS01 (Q35)
- Event ID 7 (image loaded): modules loaded by `rundll32.exe` on the SQL server (Q28)
- Event ID 11 (file creation): file names carrying the `.lsoc` extension (Q1, Q37)

## PowerShell Script-Block Logging

- Event ID 4104 queries for download and encoded-command terms, and for `Set-MpPreference` (Q7)
- Script blocks showing `Set-MpPreference -DisableRealtimeMonitoring` and `-ExclusionPath`

## Windows Security Log

- Event ID 4698 (scheduled task created) for the IT01 tasks (Q18)
- Event ID 4688 appears in a recorded query (Q37); no result for it is recorded

## Task Scheduler Log

- Event ID 106 on DC01 (`10[.]10[.]0[.]4`) listed the registered tasks; Event IDs 200 and 201 showed the actions they ran (Q17)

## MSSQL Log

- Event ID 18456 on the SQL server: 2,062 events (Q23)
- Event ID 15457: `show advanced options` and `xp_cmdshell` changed from 0 to 1 (Q24)

## IP Lookup

- The attacker address `3[.]90[.]168[.]151` resolves to `ec2-3-90-168-151[.]compute-1[.]amazonaws[.]com` (Q6)

## Base64 Decoding

- Encoded PowerShell commands were decoded with base64decode.org; decoded output is shown for Q10, Q13, Q14, Q27, Q29 to Q31 and Q33

## MITRE ATT&CK

- Recorded technique answers: T1562.001 (Q7) and T1620 (Q28)

## Notes

- The record shows the queries and views used. It does not record tool versions or collection times.
