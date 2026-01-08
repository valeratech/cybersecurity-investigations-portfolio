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
Investigate initial access via the HR job application portal, identify attacker activity (recon, exploitation, credential access), trace lateral movement into the internal network, and determine what data was accessed and/or exfiltrated during the intrusion.

### Scenario Summary
The website `hr.compliantsecure.store`, used for handling job applications, was exploited via an unrestricted file upload vulnerability. The attacker uploaded a hidden webshell, used it for reconnaissance and Active Directory enumeration, dumped LSASS process memory to extract credentials, established a tunnel for internal pivoting, accessed SMB file shares on a file server, enumerated sensitive directories, and began exfiltrating documents.

### Key Focus Areas
- Network Forensics (PCAP)
- Web exploitation and webshell activity
- Active Directory enumeration (LDAP)
- Credential access (LSASS dump parsing/cracking)
- Tunnel/pivot establishment
- SMB share access, enumeration, and exfiltration

## 2. Environment & Tools Used

### Environment Description
- HR website: `hr.compliantsecure.store`
- Compromised web server: `HRWEBSERVER` (Microsoft-IIS/10.0, ASP.NET) — `10.10.3.115`
- Domain: `AD` / `ad.compliantsecure.store`
- Domain Controller: `DC01.ad.compliantsecure.store`
- File server targeted: `FILESERVER01.ad.compliantsecure.store` — `10.10.11.216`
- Attacker source IP: `3.68.76.39`
- Remote C2 host: `52.59.195.223`

### Tools & Frameworks (Observed / Used)
- Suricata (ET/GPL alert signatures)
- Zeek (files.log, SMB mapping/metadata)
- Brim/Zui (log pivoting and filtering)
- Wireshark (stream inspection, protocol analysis, Export Objects → HTTP)
- Nmap (attacker scanning activity observed)
- PowerShell (execution via webshell)
- PowerView.ps1 / PowerSploit (AD enumeration)
- rundll32 + `comsvcs.dll` (LSASS MiniDump technique)
- Pypykatz (credential extraction from LSASS dump)
- John the Ripper + `rockyou.txt` (offline cracking)
- VirusTotal (hash reputation / classification)
- Ligolo-NG (tunneling/pivoting framework)

## 3. Evidence Collected

### Evidence Register
| Evidence ID | Description | Source | Format | Hash | Notes |
|------------|-------------|--------|--------|------|------|
| E-001 | Network packet capture (primary investigation dataset) | CyberDefenders CyberRange | PCAP | TBD | Use for Suricata/Zeek/Wireshark correlation |

**Chain of custody / integrity (initialization):**
- Hash the PCAP upon download/export and update the Evidence Register.
- Store any exported objects (e.g., `lsass.dmp`, `agent.exe`) as separate evidence items with hashes.

## 4. Analysis & Findings

> All timestamps are treated as **UTC** unless explicitly stated otherwise.

### Current Findings (Known)
- **Initial attacker IP (directory enumeration):** `3.68.76.39`
- **Recon scanning tool:** `nmap`
- **Uploaded webshell filename:** `mycv.aspx`
- **Webshell auth cookie:** `shell_pass=u_h@ck3d`
- **First webshell command:** `ipconfig /all`
- **AD enumeration tool (in-memory):** `PowerView.ps1`
- **Primary protocol for AD recon:** `LDAP`
- **File server targeted for SMB enumeration:** `FILESERVER01.ad.compliantsecure.store`
- **LSASS dump DLL:** `comsvcs.dll`
- **LSASS dump download attempt:** `2025-05-20 18:48Z`
- **C2 payload URL:** `http://52.59.195.223/agent.exe`
- **Tunnel tool identified:** `Ligolo-NG`
- **Tunnel established:** `2025-05-20 19:07Z`
- **SMB share access attempt (using Michael creds):** `2025-05-20 19:14Z`
- **Sensitive directories discovered:** `Documents`, `Finance`, `HR`, `IT`, `Programs`
- **First PDF exfiltrated:** `company_policy_manual.pdf`


## 5. Timeline (UTC)

- 2025-05-20 18:15Z — Directory enumeration activity observed against HR web server from `3.68.76.39`
- 2025-05-20 18:28Z — Webshell upload detected (`mycv.aspx`)
- 2025-05-20 18:48Z — LSASS dump (`lsass.dmp`) download attempted via webshell
- 2025-05-20 19:07Z — Tunnel connection established between `10.10.3.115` and `52.59.195.223`
- 2025-05-20 19:14Z — SMB share access attempted against `10.10.11.216` (File Server)
- 2025-05-20 19:15Z — Share directory enumeration returns sensitive folder names
- (TBD) — Confirm earliest timestamp for first PDF read/exfil transaction on SMB


## 6. Indicators of Compromise (IOCs)

### Network
- Attacker IP: `3.68.76.39`
- C2 IP: `52.59.195.223`
- URL: `http://52.59.195.223/agent.exe`

### Web
- Webshell: `mycv.aspx`
- Webshell auth cookie: `shell_pass=u_h@ck3d`

### Credential Access
- LSASS dump method: `rundll32.exe` + `comsvcs.dll` → `lsass.dmp`

### Lateral Movement / Discovery
- SMB target: `FILESERVER01.ad.compliantsecure.store` (`10.10.11.216`)
- Share browsed: `\\10.10.11.216\Shares`

## 7. Repo Notes (How this case is organized)
- `case-notes/` — narrative notes per step/question with packet/frame references
- `evidence-metadata/` — evidence register, hashes, extracted objects metadata, IOC lists
- `analysis/` — structured findings (filters used, correlations, timelines)
- `pcaps/` — original PCAP and/or working copies (do not modify originals)
- `scripts/` — commands used (pypykatz/john filters, extraction notes)
- `reports/` — final written report once completed
