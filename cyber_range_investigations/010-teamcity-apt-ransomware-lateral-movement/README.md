# Investigation Report – TeamCity APT Ransomware

**Document Type:** Case Overview  
**Case Title:** TeamCity APT Ransomware – Lateral Movement & Data Exfiltration  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Documentation Started:** 2026-04-16  
**Documentation Last Updated:** 2026-09-28  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Case Contents

### Analysis

- [Findings Summary](analysis/findings-summary.md)
- [Network Analysis](analysis/network-analysis.md)
- [Timeline](analysis/timeline-utc.md)

### Case Notes

- [Analysis Tools and Methods](case-notes/analysis-tools-and-methods.md)
- [Investigation Procedure and Findings](case-notes/investigation-procedure-and-findings.md)

### Evidence Metadata

- [Evidence Inventory](evidence-metadata/evidence-inventory.md)
- [Tools Usage Documentation](evidence-metadata/tools-usage-documentation.md)

### Indicators of Compromise

- [Network IOCs](iocs/network-iocs.md)

### Reports

- [Final Report](reports/final-report.md)

### Supporting Directories

Directory notes: [scripts](scripts/README.md), [pcaps](pcaps/README.md), [screenshots](screenshots/README.md).

## 1. Overview

### Objective

Answer the structured question set for this scenario and document each answer with its record basis, from initial access through ransomware execution.

### Scenario Summary

The scenario describes an attack on CyberRange in August 2024 by an advanced persistent threat group, ending in ransomware deployment across the network. The SOC detected files encrypted with an unknown extension and a ransom note claiming data theft.
The question set states that initial access came through a TeamCity server using CVE-2024-27198. The recorded answers name the compromised TeamCity URL host `jb[.]cyberrange[.]cyberdefenders[.]org` and the beachhead host `JB01`.
The record then shows defence evasion and a command-and-control tunnel on JB01; reconnaissance, brute force and credential-dumping attempts on the SQL server; Invoke-Mimikatz and scheduled tasks on DC01; `wmic /node` execution against four internal addresses; files staged for exfiltration; and encryption with the `.lsoc` extension.

### Key Focus Areas

- Log analysis in Elastic with KQL
- PowerShell script blocks and decoded commands
- Command and control, lateral movement and persistence
- Credential access
- Exfiltration staging and ransomware impact

## 2. Environment & Tools Used

### Environment Shown in the Record

- Domain: `cyberrange[.]cyberdefenders[.]org`
- DMZ `10[.]10[.]3[.]0/24`, with the WAF (NGINX) at `10[.]10[.]3[.]6` and JB01 at `10[.]10[.]3[.]4` (network-diagram excerpt)
- SQL server: `10[.]10[.]0[.]6`
- DC01: `10[.]10[.]0[.]4`
- FS01: `10[.]10[.]0[.]7`
- IT01: `10[.]10[.]1[.]4`
- A further `wmic /node` target, `10[.]10[.]0[.]5`, whose hostname is not recorded

### Tools & Frameworks

- Elastic (Kibana Discover, field statistics, KQL)
- Sysmon (Event IDs 1, 7, 11)
- Windows event logs: PowerShell 4104, Security 4698, Task Scheduler 106, 200 and 201, MSSQL 18456 and 15457
- A web Base64 decoder (base64decode.org)
- IP lookup (Q6) and MITRE ATT&CK (Q7, Q28)

## 3. Evidence Collected

The case record is the analyst's notes for the 38-question set, with embedded screenshots.

See:
- [`evidence-metadata/evidence-inventory.md`](evidence-metadata/evidence-inventory.md)

## 4. Analysis & Findings

### 4.1 Initial Indicators

- Files encrypted with the `.lsoc` extension
- Ransom note `un-lock your files[.]html`
- Attacker address `3[.]90[.]168[.]151`
- Encoded PowerShell command lines on JB01

### 4.2 Timeline Reconstruction

See:
- [`analysis/timeline-utc.md`](analysis/timeline-utc.md)

### 4.3 Host-Based Analysis

- Defender real-time monitoring disabled and exclusions added with `Set-MpPreference` (T1562.001)
- Registry values `NoLMHash` and `DisableRestrictedAdmin` modified to facilitate credential harvesting
- Scheduled tasks on DC01 and IT01
- Credential dumping attempted with EDRSandblast on the SQL server and with Invoke-Mimikatz on DC01

### 4.4 Network Analysis

- Initial access through the TeamCity service `jb[.]cyberrange[.]cyberdefenders[.]org`; the question states CVE-2024-27198
- Attacker address `3[.]90[.]168[.]151`; IP lookup returns `ec2-3-90-168-151[.]compute-1[.]amazonaws[.]com`
- A firewall rule allowing inbound TCP 8080, and a tunnel to `3[.]90[.]168[.]151:8443`

### 4.5 In-Memory Execution

- The question describes Cobalt Strike's execute-assembly on the SQL server; the recorded technique is T1620, and `rundll32.exe` loads `clrjit.dll`

### 4.6 Malware Behavior

- The question set describes the beacons as Cobalt Strike; the record shows `rundll32` running four DLLs through `wmic /node`
- Ransomware encryption and the shadow-copy deletion command `vssadmin.exe Delete Shadows /All /Quiet`

## 5. Findings Summary

- Initial access: TeamCity service, per the question's CVE-2024-27198 premise
- Beachhead host: `JB01` (`10[.]10[.]3[.]4`)
- Defence evasion: Defender disabled (T1562.001)
- Credential access: EDRSandblast with a vulnerable driver, and Invoke-Mimikatz; outcomes not recorded
- Lateral movement: `wmic /node`, DLLs run by `rundll32`, and an impersonated account
- Persistence: scheduled tasks on DC01 and IT01
- Exfiltration staging: steganography and compression; no transfer recorded
- Impact: ransomware encryption with the `.lsoc` extension

See:
- [`analysis/findings-summary.md`](analysis/findings-summary.md)
- [`reports/final-report.md`](reports/final-report.md)

## 6. Impact Assessment

- Files encrypted and ransom notes written
- A shadow-copy deletion command run during the ransomware phase
- Credential-dumping attempts on the SQL server and DC01; their outcome is not recorded
- Files staged for exfiltration; no transfer is recorded

## 7. Indicators of Compromise (IOCs)

See:
- [`iocs/network-iocs.md`](iocs/network-iocs.md)

## 8. Reports

- [`reports/final-report.md`](reports/final-report.md)

## 9. Case Status

**Status:** Complete  
