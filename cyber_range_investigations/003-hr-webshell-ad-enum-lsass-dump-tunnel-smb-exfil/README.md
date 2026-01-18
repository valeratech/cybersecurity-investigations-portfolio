# Investigation Report

**Case Title:** HR Webshell → AD Enum → LSASS Dump → Tunnel Pivot → SMB Exfil  
**Case ID:** 003  
**Date Created:** 2026-01-08  
**Last Updated:** 2026-01-08  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Overview

### Objective
Investigate initial access via the HR job application portal, identify attacker activity (reconnaissance, exploitation, credential access), trace lateral movement into the internal network, and determine what data was accessed and/or exfiltrated during the intrusion.

### Scenario Summary
The website `hr.compliantsecure.store`, used for handling job applications, was exploited via an unrestricted file upload vulnerability. The attacker uploaded a hidden webshell, used it for host and network reconnaissance, performed Active Directory enumeration, dumped LSASS process memory to extract credentials, established a tunnel for internal pivoting, accessed SMB file shares on an internal file server, enumerated sensitive directories, and exfiltrated internal documents.

### Key Focus Areas
- Network forensics (PCAP-based analysis)
- Web exploitation and webshell activity
- Active Directory enumeration (LDAP)
- Credential access (LSASS dump parsing and cracking)
- Tunnel and pivot establishment
- SMB share access, enumeration, and data exfiltration

## 2. Environment & Tools Used

### Environment Description
- HR website: `hr.compliantsecure.store`
- Compromised web server: `HRWEBSERVER` (Microsoft-IIS/10.0, ASP.NET) — `10.10.3.115`
- Active Directory domain: `AD` / `ad.compliantsecure.store`
- Domain Controller: `DC01.ad.compliantsecure.store`
- File server targeted: `FILESERVER01.ad.compliantsecure.store` — `10.10.11.216`
- Attacker source IP: `3.68.76.39`
- Remote C2 host: `52.59.195.223`

### Tools & Frameworks (Observed / Used)
- Suricata (ET / GPL alert signatures)
- Zeek (files.log, SMB metadata, HTTP transactions)
- Brim / Zui (log pivoting and correlation)
- Wireshark (stream inspection, protocol analysis, HTTP object extraction)
- Nmap (attacker reconnaissance activity)
- PowerShell (execution via webshell)
- PowerView.ps1 / PowerSploit (Active Directory enumeration)
- `rundll32.exe` + `comsvcs.dll` (LSASS MiniDump technique)
- Pypykatz (credential extraction from LSASS dump)
- John the Ripper with `rockyou.txt` (offline password cracking)
- VirusTotal (malware classification and reputation)
- Ligolo-NG (tunneling and network pivoting framework)

## 3. Evidence Collected

### Evidence Register (Summary)
| Evidence ID | Description | Source | Format | Hash | Notes |
|------------|-------------|--------|--------|------|------|
| E-001 | Network traffic capture (primary dataset) | CyberDefenders CyberRange | PCAP | N/A | Accessed in CyberRange VM only |
| E-002 | LSASS process memory dump | Compromised host | DMP | N/A | Extracted and analyzed within range |
| E-003 | Credential extraction output | Analyst-generated | TXT | N/A | Derived from LSASS dump |
| E-004 | Malicious payload | External C2 | EXE | SHA256 documented | `agent.exe` |

Detailed evidence handling, integrity notes, and platform constraints are documented in `evidence-metadata/`.

### Chain-of-Custody & Integrity Notes
- Raw PCAP data was **not exportable** from the CyberDefenders CyberRange.
- All network analysis was performed **in situ** using Zeek, Brim/Zui, and Wireshark.
- Evidence was not modified outside the controlled lab environment.
- All timestamps referenced throughout the investigation are normalized to **UTC**.

## 4. Analysis & Findings

### Confirmed Findings
- **Initial attacker IP:** `3.68.76.39`
- **Reconnaissance scanning tool:** `nmap`
- **Uploaded webshell:** `mycv.aspx`
- **Webshell authentication cookie:** `shell_pass=u_h@ck3d`
- **First command executed via webshell:** `ipconfig /all`
- **AD enumeration tool (in-memory):** `PowerView.ps1`
- **Primary AD reconnaissance protocol:** `LDAP`
- **Targeted file server:** `FILESERVER01.ad.compliantsecure.store`
- **LSASS dump technique:** `rundll32.exe` with `comsvcs.dll`
- **LSASS dump download:** `2025-05-20 18:48Z`
- **Malicious payload URL:** `http://52.59.195.223/agent.exe`
- **Tunnel framework:** Ligolo-NG
- **Tunnel established:** `2025-05-20 19:07Z`
- **Authenticated SMB access (Michael):** `2025-05-20 19:14Z`
- **Sensitive directories discovered:** `Documents`, `Finance`, `HR`, `IT`, `Programs`
- **First confirmed exfiltrated PDF:** `company_policy_manual.pdf`

## 5. Timeline (UTC)

- **2025-05-20 18:15Z** — Directory enumeration against HR web server from `3.68.76.39`
- **2025-05-20 18:28Z** — Webshell uploaded (`mycv.aspx`)
- **2025-05-20 18:48Z** — LSASS dump (`lsass.dmp`) downloaded via webshell
- **2025-05-20 19:07Z** — Tunnel established between `10.10.3.115` and `52.59.195.223`
- **2025-05-20 19:14Z** — Authenticated SMB access to `FILESERVER01`
- **2025-05-20 19:15Z** — SMB share enumeration and initial file access observed
- **2025-05-20 19:15Z+** — Internal documents accessed and exfiltrated

## 6. Indicators of Compromise (IOCs)

### Network
- Attacker IP: `3.68.76.39`
- C2 IP: `52.59.195.223`
- Malicious URL: `http://52.59.195.223/agent.exe`

### Web
- Webshell file: `mycv.aspx`
- Authentication cookie: `shell_pass=u_h@ck3d`

### Credential Access
- LSASS dump method: `rundll32.exe` + `comsvcs.dll`
- Dump file: `lsass.dmp`

### Lateral Movement & Discovery
- SMB target: `FILESERVER01.ad.compliantsecure.store` (`10.10.11.216`)
- Share accessed: `\\10.10.11.216\Shares`

## 7. Repository Structure & Notes

- `case-notes/` — Narrative notes and packet/frame references
- `evidence-metadata/` — Evidence register, handling notes, integrity constraints
- `analysis/` — Structured findings, filters used, timelines, ATT&CK mapping
- `pcaps/` — Documentation of PCAP access and analysis (raw PCAP retained in CyberRange VM)
- `scripts/` — Commands and tooling references used during analysis
- `reports/` — Final investigation report and summaries

**End of Investigation README**
