# Investigation Report – TeamCity APT Ransomware

**Document Type:** Investigation Summary (Root README)

**Case Title:** TeamCity APT Ransomware – Lateral Movement & Data Exfiltration  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Date Created:** 2026-04-16  
**Last Updated:** 2026-04-16  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Overview

### Objective
Perform a full-scope DFIR investigation to identify initial access via TeamCity exploitation, trace attacker activity across the network, analyze lateral movement, credential access, persistence mechanisms, and ransomware execution, and extract confirmed indicators of compromise.

### Scenario Summary
In August 2024, a sophisticated advanced persistent threat (APT) leveraged a critical vulnerability in a TeamCity server to gain initial access into the CyberRange environment. The attacker established a beachhead host in the DMZ, disabled security controls, deployed command-and-control mechanisms, and performed extensive reconnaissance across internal systems.

The attack escalated to lateral movement across infrastructure systems including SQL Server, Domain Controller, and File Server. The adversary deployed multiple beacons, executed credential dumping techniques, abused Windows native tools (LOLBins), and staged data for exfiltration using steganography and compression techniques.

The attack concluded with widespread ransomware deployment, encrypting files with a `.lsoc` extension and dropping ransom notes across compromised systems.

### Key Focus Areas
- Network Forensics  
- Endpoint & Host-Based Analysis  
- Threat Hunting (Elastic / Sysmon / PowerShell Logs)  
- Malware & Ransomware Behavior  
- Lateral Movement & Privilege Escalation  
- Credential Dumping & Defense Evasion  
- Incident Reconstruction  

## 2. Environment & Tools Used

### Environment Description
- Domain: `cyberrange[.]cyberdefenders[.]org`  
- Address Space: `10[.]10[.]0[.]0/16`  
- Firewall: pfSense  

#### Network Segments
- DMZ: `10[.]10[.]3[.]0/24`  
- Infrastructure: `10[.]10[.]0[.]0/24`  
- Workstations: `10[.]10[.]1[.]0/24`  
- Blue Team Stack: `10[.]10[.]4[.]0/24`  

#### Key Systems
- Web Server: `10[.]10[.]3[.]6`  
- Beachhead Host (JB01): `10[.]10[.]3[.]4`  
- Domain Controller (DC01): `10[.]10[.]0[.]4`  
- SQL Server: `10[.]10[.]0[.]6`  
- File Server: `10[.]10[.]0[.]7`  
- IT Workstation (IT01): `10[.]10[.]1[.]4`  

### Tools & Frameworks
- Elastic (KQL Queries)  
- Sysmon (Event IDs 1, 7, 10, 11)  
- Windows Event Logs (Security, PowerShell 4104, Task Scheduler)  
- PowerShell (Script Block Analysis / Base64 Decoding)  
- MITRE ATT&CK Framework  
- Reverse DNS Lookup  
- Base64 Decoding Tools  

## 3. Evidence Collected

### Evidence Artifacts
- Pre-parsed Elastic logs (multi-host telemetry)  
- Sysmon logs (process, file, module, network activity)  
- PowerShell script block logs (Event ID 4104)  
- Windows Security logs (Event IDs 4688, 4698)  
- Task Scheduler logs (Event IDs 106, 200, 201)  
- MSSQL logs (Event ID 18456, configuration changes)  

See:
- `evidence-metadata/evidence-inventory.md`

## 4. Analysis & Findings

### 4.1 Initial Indicators
- File encryption with `.lsoc` extension  
- Presence of ransom note: `un-lock your files[.]html`  
- Suspicious external IP communication: `3[.]90[.]168[.]151`  
- Unusual PowerShell execution activity  

### 4.2 Timeline Reconstruction
See:
- `analysis/timeline-utc.md`

### 4.3 Host-Based Analysis
- Defender disabled via `Set-MpPreference`  
- Registry modifications for credential harvesting  
- Scheduled task persistence on DC01 and IT01  
- LSASS credential dumping attempts  

### 4.4 Network Analysis
- Initial access via TeamCity exploitation (CVE-2024-27198)  
- External attacker IP: `3[.]90[.]168[.]151`  
- Reverse DNS: `ec2-3-90-168-151.compute-1.amazonaws[.]com`  
- C2 tunneling via port `8080`  

### 4.5 Memory Analysis (if applicable)
- In-memory execution via reflective code loading (T1620)  

### 4.6 Malware Behavior
- Deployment of Cobalt Strike beacons  
- Execution via `rundll32`  
- Use of `wmic` for remote execution  
- Ransomware encryption and shadow copy deletion  

## 5. Confirmed Findings (Executive Summary)

- Initial Access: TeamCity exploitation (CVE-2024-27198)  
- Beachhead Host: `JB01 (10[.]10[.]3[.]4)`  
- Defense Evasion: Disabled Defender (T1562.001)  
- Credential Access: LSASS dumping via EDR bypass tools  
- Lateral Movement: WMIC, DLL execution, user impersonation  
- Persistence: Scheduled tasks and registry modifications  
- Data Exfiltration: Steganography + compression  
- Impact: Ransomware deployment with `.lsoc` encryption  

See:
- `analysis/findings-summary.md`
- `reports/010-teamcity-apt-ransomware-lateral-movement-report.md`

## 6. Impact Assessment

- Enterprise-wide ransomware encryption  
- Credential compromise across multiple hosts  
- Active Directory compromise risk  
- Data exfiltration via covert techniques  

## 7. Indicators of Compromise (IOCs)

See:
- `iocs/network-iocs.md`

## 8. Reports

- `reports/010-teamcity-apt-ransomware-lateral-movement-report.md`

## 9. Case Status

**Status:** In Progress  
**Confidence Level:** High  
**Report Ready:** No  
