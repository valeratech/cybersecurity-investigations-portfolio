# Cybersecurity Investigations Portfolio

This repository is a central collection of my cybersecurity investigations completed across CyberRange and lab environments. It serves as a structured record of hands-on **DFIR, SIEM investigation, threat hunting, memory, disk, and network forensics** work.

Current investigations:

- **CyberDefenders** — 9 investigations: artifact-driven challenges centered on real-world memory, endpoint, and network forensics  
- **Security Blue Team (BTLO)** — 1 investigation: operationally-focused labs simulating real-world SOC environments  

All investigations follow a consistent methodology, typically including:

- Case objectives and scenario background  
- Evidence collection and structured forensic analysis  
- Detection logic and log analysis (**Splunk SPL, KQL, Sigma, Zeek, Suricata**)  
- Timeline reconstruction, IOCs, and attacker TTP mapping  
- Final findings and remediation recommendations  

## Investigation Index

| Case | Investigation | Platform | Status | Final Report | Timeline | IOCs |
|:---|:---|:---|:---|:---|:---|:---|
| 001 | [Macro Malware Data Exfiltration — Network Forensics](cyber_range_investigations/001-macro-malware-data-exfiltration/README.md) | CyberDefenders | Complete | [Report](cyber_range_investigations/001-macro-malware-data-exfiltration/reports/final-report.md) | [Timeline](cyber_range_investigations/001-macro-malware-data-exfiltration/analysis/timeline-utc.md) | [IOCs](cyber_range_investigations/001-macro-malware-data-exfiltration/iocs/network-iocs.md) |
| 002 | [Web Upload Abuse → Cobalt Strike C2 → Lateral Movement & Attempted Exfiltration](cyber_range_investigations/002-web-upload-cobalt-strike-lateral-exfiltration/README.md) | CyberDefenders | Complete | [Report](cyber_range_investigations/002-web-upload-cobalt-strike-lateral-exfiltration/reports/final-report.md) | [Timeline](cyber_range_investigations/002-web-upload-cobalt-strike-lateral-exfiltration/analysis/timeline-utc.md) | [IOCs](cyber_range_investigations/002-web-upload-cobalt-strike-lateral-exfiltration/iocs/network-iocs.md) |
| 003 | [HR Webshell → AD Enum → LSASS Dump → Tunnel Pivot → SMB Enumeration](cyber_range_investigations/003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil/README.md) | CyberDefenders | Complete | [Report](cyber_range_investigations/003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil/reports/final-report.md) | [Timeline](cyber_range_investigations/003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil/README.md#5-timeline-utc) | [IOCs](cyber_range_investigations/003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil/README.md#6-indicators-of-compromise-iocs) |
| 004 | [Office RTF (Equation Editor) → PowerShell Persistence → C2](cyber_range_investigations/004-office-rtf-eqn-editor-powershell-c2/README.md) | CyberDefenders | Complete | [Report](cyber_range_investigations/004-office-rtf-eqn-editor-powershell-c2/reports/final-report.md) | [Timeline](cyber_range_investigations/004-office-rtf-eqn-editor-powershell-c2/case-notes/timeline.md) | [IOCs](cyber_range_investigations/004-office-rtf-eqn-editor-powershell-c2/README.md#5-indicators-of-compromise-iocs-defanged) |
| 005 | [Disk Forensics — Telegram-delivered Covenant, mimikatz Masquerade, Persistence](cyber_range_investigations/005-telegram-covenant-mimikatz-persistence/README.md) | CyberDefenders | Complete | [Report](cyber_range_investigations/005-telegram-covenant-mimikatz-persistence/reports/final-report.md) | [Timeline](cyber_range_investigations/005-telegram-covenant-mimikatz-persistence/analysis/timeline-utc.md) | — |
| 006 | [WMI-Spawned PowerShell with LSASS Credential Dump](cyber_range_investigations/006-memory-forensics-wmi-powershell-lsass-dump/README.md) | CyberDefenders | Complete | [Report](cyber_range_investigations/006-memory-forensics-wmi-powershell-lsass-dump/reports/final-report.md) | [Timeline](cyber_range_investigations/006-memory-forensics-wmi-powershell-lsass-dump/analysis/timeline-reconstruction.md) | [IOCs](cyber_range_investigations/006-memory-forensics-wmi-powershell-lsass-dump/analysis/iocs.md) |
| 007 | [Memory EVTX Extraction, RDP Intrusion, WMIC Lateral Movement, LSASS Dump](cyber_range_investigations/007-memory-evtx-extraction-rdp-wmic-lsass-dump/README.md) | CyberDefenders | In Progress | [Pending](cyber_range_investigations/007-memory-evtx-extraction-rdp-wmic-lsass-dump/reports/README.md) | [Timeline](cyber_range_investigations/007-memory-evtx-extraction-rdp-wmic-lsass-dump/analysis/timeline.md) | [IOCs](cyber_range_investigations/007-memory-evtx-extraction-rdp-wmic-lsass-dump/README.md#5-indicators-of-compromise-defanged) |
| 008 | [SSH Brute-Force, Authentication Abuse, and Post-Exploitation](cyber_range_investigations/008-ssh-bruteforce-auth-abuse-post-exploitation/README.md) | CyberDefenders | Complete | [Report](cyber_range_investigations/008-ssh-bruteforce-auth-abuse-post-exploitation/reports/final-report.md) | [Timeline](cyber_range_investigations/008-ssh-bruteforce-auth-abuse-post-exploitation/analysis/timeline-utc.md) | [IOCs](cyber_range_investigations/008-ssh-bruteforce-auth-abuse-post-exploitation/iocs/network-iocs.md) |
| 009 | [OSK Hijack Persistence and Cerber Botnet Activity](cyber_range_investigations/009-osk-hijack-cerber-botnet/README.md) | Security Blue Team | Complete | [Report](cyber_range_investigations/009-osk-hijack-cerber-botnet/reports/final-report.md) | [Timeline](cyber_range_investigations/009-osk-hijack-cerber-botnet/analysis/timeline-utc.md) | [IOCs](cyber_range_investigations/009-osk-hijack-cerber-botnet/iocs/network-iocs.md) |
| 010 | [TeamCity APT Ransomware — Lateral Movement & Data Exfiltration](cyber_range_investigations/010-teamcity-apt-ransomware-lateral-movement/README.md) | CyberDefenders | Complete | [Report](cyber_range_investigations/010-teamcity-apt-ransomware-lateral-movement/reports/final-report.md) | [Timeline](cyber_range_investigations/010-teamcity-apt-ransomware-lateral-movement/analysis/timeline-utc.md) | [IOCs](cyber_range_investigations/010-teamcity-apt-ransomware-lateral-movement/iocs/network-iocs.md) |

Cases 003, 004 and 007 record their indicators within the case README rather than a
dedicated IOC document; those links point to the relevant section. Case 003's timeline
is likewise recorded in its README. Case 005 has no observed-indicator document.

## Investigation Methodology

Each investigation follows a structured, analyst-driven workflow:

- Data acquisition and initial triage  
- Log and artifact analysis (Splunk, endpoint, network, memory)  
- Query development and iterative refinement (SPL, KQL, etc.)  
- Event correlation and timeline reconstruction  
- Identification of suspicious patterns and attacker behavior  
- Validation of findings with supporting evidence  
- Documentation of results, including queries, reasoning, and conclusions  

> **Note:** All data in this repository is generated in lab environments or fully sanitized.  
> No real-world client or sensitive information is included.

For the standard case-report structure, see the
[Investigation Report Template](TEMPLATE_Investigation_Report.md).
Document structure, metadata, terminology and evidence-attribution rules are
specified in [docs/SCHEMA.md](docs/SCHEMA.md).

## Case Status

- **Complete** — the cyber-range exercise was finished, its final question
  answered, and the portfolio report and supporting documentation finalized.
- **In Progress** — the exercise, analysis, evidence collection, or portfolio
  documentation remains unfinished.

Status describes the state of this repository's documentation, not a formal
closure process within the range platform.

## Date Fields

Documentation timestamps describe when the portfolio case study was written.
They are not investigation timestamps. Where the date of the underlying
range activity was not recorded, it is stated as such rather than inferred.

## Indicator Handling Convention

Indicators of compromise in this repository are **defanged** in prose, IOC
tables and inline references (`192[.]168[.]1[.]1`, `hxxp://`). Indicators
inside fenced code blocks are left in their original form so that documented
queries and filters remain directly runnable - re-fang deliberately before
reuse.

Recovered credential material is masked. Password hashes are truncated and
plaintext passwords are redacted; where password *characteristics* are
analytically relevant they are described rather than reproduced.

## Repository Structure

```text
cybersecurity-investigations-portfolio/
├── README.md
├── TEMPLATE_Investigation_Report.md
└── cyber_range_investigations/
    ├── 001-macro-malware-data-exfiltration/
    └── ...
```
