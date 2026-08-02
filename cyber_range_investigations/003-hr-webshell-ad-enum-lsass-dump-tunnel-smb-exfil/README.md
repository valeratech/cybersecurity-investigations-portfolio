# Investigation Report

**Case Title:** HR Webshell → AD Enum → LSASS Dump → Tunnel Pivot → SMB Exfil  
**Case ID:** 003  
**Documentation Started:** 2026-01-08  
**Documentation Last Updated:** 2026-01-18  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Case Contents

### Analysis

- [Alert Triage Signatures and Filters](analysis/001-alert-triage-signatures-and-filters.md)
- [Network Scan and Recon Attribution](analysis/002-network-scan-and-recon-attribution.md)
- [Webshell Upload and HTTP Exploitation](analysis/003-webshell-upload-and-http-exploitation.md)
- [Webshell Authentication and Command Execution](analysis/004-webshell-authentication-and-command-execution.md)
- [Active Directory Enumeration (PowerShell)](analysis/005-active-directory-enumeration-powershell.md)
- [Internal Host Targeting and SMB Discovery](analysis/006-internal-host-targeting-and-smb-discovery.md)
- [LSASS Dump and Credential Access](analysis/007-lsass-dump-and-credential-access.md)
- [LSASS Dump Retrieval and Offline Credential Extraction](analysis/008-lsass-dump-retrieval-and-offline-credential-extraction.md)
- [Authenticated SMB Access and Lateral Movement](analysis/009-authenticated-smb-access-and-lateral-movement.md)
- [SMB Share Enumeration and Sensitive Data Discovery](analysis/010-smb-share-enumeration-and-sensitive-data-discovery.md)
- [SMB File Access and Data Exfiltration](analysis/011-smb-file-access-and-data-exfiltration.md)
- [Impact Assessment and Investigation Summary](analysis/012-impact-assessment-and-investigation-summary.md)

### Case Notes

- [Initial Scope and Alert Triage](case-notes/initial-scope-and-alert-triage.md)

### Evidence Metadata

- [Evidence Handling and Limitations](evidence-metadata/evidence-handling-and-limitations.md)
- [Evidence Register](evidence-metadata/evidence-register.md)

### Reports

- [Final Report](reports/final-report.md)

### Supporting Directories

Evidence-handling notes for artifacts excluded from version control: [pcaps](pcaps/README.md).

## 1. Overview

### Objective
Investigate initial access via the HR job application portal, identify attacker activity (reconnaissance, exploitation, credential access), trace lateral movement into the internal network, and determine what data was accessed and/or exfiltrated during the intrusion.

### Scenario Summary
The website `hr[.]compliantsecure[.]store`, used for handling job applications, was exploited via an unrestricted file upload vulnerability. The attacker uploaded a hidden webshell, used it for host and network reconnaissance, performed Active Directory enumeration, dumped LSASS process memory to extract credentials, established a tunnel for internal pivoting, accessed SMB file shares on an internal file server, enumerated sensitive directories, and exfiltrated internal documents.

### Key Focus Areas
- Network forensics (PCAP-based analysis)
- Web exploitation and webshell activity
- Active Directory enumeration (LDAP)
- Credential access (LSASS dump parsing and cracking)
- Tunnel and pivot establishment
- SMB share access, enumeration, and data exfiltration

## 2. Environment & Tools Used

### Environment Description
- HR website: `hr[.]compliantsecure[.]store`
- Compromised web server: `HRWEBSERVER` (Microsoft-IIS/10.0, ASP.NET) — `10[.]10[.]3[.]115`
- Active Directory domain: `AD` / `ad[.]compliantsecure[.]store`
- Domain Controller: `DC01[.]ad[.]compliantsecure[.]store`
- File server targeted: `FILESERVER01[.]ad[.]compliantsecure[.]store` — `10[.]10[.]11[.]216`
- Attacker source IP: `3[.]68[.]76[.]39`
- Remote C2 host: `52[.]59[.]195[.]223`

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
- **Initial attacker IP:** `3[.]68[.]76[.]39`
- **Reconnaissance scanning tool:** `nmap`
- **Uploaded webshell:** `mycv.aspx`
- **Webshell authentication cookie:** `shell_pass=u_h@ck3d`
- **First command executed via webshell:** `ipconfig /all`
- **AD enumeration tool (in-memory):** `PowerView.ps1`
- **Primary AD reconnaissance protocol:** `LDAP`
- **Targeted file server:** `FILESERVER01[.]ad[.]compliantsecure[.]store`
- **LSASS dump technique:** `rundll32.exe` with `comsvcs.dll`
- **LSASS dump download:** `2025-05-20 18:48Z`
- **Malicious payload URL:** `hxxp://52[.]59[.]195[.]223/agent.exe`
- **Tunnel framework:** Ligolo-NG
- **Tunnel established:** `2025-05-20 19:07Z`
- **Authenticated SMB access (Michael):** `2025-05-20 19:14Z`
- **Sensitive directories discovered:** `Documents`, `Finance`, `HR`, `IT`, `Programs`
- **First confirmed exfiltrated PDF:** `company_policy_manual.pdf`

## 5. Timeline (UTC)

- **2025-05-20 18:15Z** — Directory enumeration against HR web server from `3[.]68[.]76[.]39`
- **2025-05-20 18:28Z** — Webshell uploaded (`mycv.aspx`)
- **2025-05-20 18:48Z** — LSASS dump (`lsass.dmp`) downloaded via webshell
- **2025-05-20 19:07Z** — Tunnel established between `10[.]10[.]3[.]115` and `52[.]59[.]195[.]223`
- **2025-05-20 19:14Z** — Authenticated SMB access to `FILESERVER01`
- **2025-05-20 19:15Z** — SMB share enumeration and initial file access observed
- **2025-05-20 19:15Z+** — Internal documents accessed and exfiltrated

## 6. Indicators of Compromise (IOCs)

### Network
- Attacker IP: `3[.]68[.]76[.]39`
- C2 IP: `52[.]59[.]195[.]223`
- Malicious URL: `hxxp://52[.]59[.]195[.]223/agent.exe`

### Web
- Webshell file: `mycv.aspx`
- Authentication cookie: `shell_pass=u_h@ck3d`

### Credential Access
- LSASS dump method: `rundll32.exe` + `comsvcs.dll`
- Dump file: `lsass.dmp`

### Lateral Movement & Discovery
- SMB target: `FILESERVER01[.]ad[.]compliantsecure[.]store` (`10[.]10[.]11[.]216`)
- Share accessed: `\\10[.]10[.]11[.]216\Shares`

## 7. Case Status

**Status:** Complete  
**Confidence Level:** High  

**End of Investigation README**
