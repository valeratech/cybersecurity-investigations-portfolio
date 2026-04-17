# Final Investigation Report – TeamCity APT Ransomware

**Document Type:** Report

**Case Title:** TeamCity APT Ransomware – Lateral Movement & Data Exfiltration  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Date Created:** 2026-04-16  
**Last Updated:** 2026-04-16  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## 1. Executive Summary

This investigation confirms a full-scale advanced persistent threat (APT) compromise within the CyberRange environment, resulting in lateral movement across critical infrastructure systems and eventual ransomware deployment.

The attacker exploited a vulnerable TeamCity server to gain initial access, established a foothold on a DMZ host, and rapidly expanded access across the network. Through a combination of defense evasion, credential harvesting, and abuse of legitimate administrative tools, the adversary achieved domain-level impact.

The attack culminated in data exfiltration and enterprise-wide ransomware execution, encrypting files and disrupting system availability.

## 2. Scope and Objectives

### Scope
- Full CyberRange environment
- DMZ, Infrastructure, and Workstation subnets
- Multi-host log correlation using Elastic

### Objectives
- Identify initial access vector
- Trace attacker movement across the network
- Analyze persistence and privilege escalation
- Identify data exfiltration techniques
- Document ransomware execution and impact
- Extract confirmed indicators of compromise

## 3. Initial Access

The attacker gained access by exploiting a vulnerability in a TeamCity server (CVE-2024-27198).

### Key Findings
- Compromised host:
  - `jb01[.]cyberrange[.]cyberdefenders[.]org`
- Beachhead system:
  - `JB01 (10[.]10[.]3[.]4)`
- Attacker infrastructure:
  - IP: `3[.]90[.]168[.]151`
  - FQDN: `ec2-3-90-168-151.compute-1.amazonaws[.]com`

## 4. Defense Evasion

The attacker disabled and modified security controls to avoid detection.

### Techniques Observed
- Disabled Microsoft Defender:
  - `Set-MpPreference -DisableRealtimeMonitoring $true`
- Added exclusion paths:
  - `C:\TeamCity`
  - `C:\Windows`
- Created firewall rule:
  - Allowed inbound communication on port `8080`

### MITRE Mapping
- T1562.001 – Impair Defenses

## 5. Persistence

Persistence was established across multiple systems using scheduled tasks.

### Key Findings
- Domain Controller tasks:
  - `SubmitReporting`
  - `Scheduled AutoCheck`
- IT workstation persistence via scheduled task execution

## 6. Credential Access

The attacker successfully harvested credentials from compromised systems.

### Techniques Observed
- Tool used:
  - `EDRSandblast.exe`
- Vulnerable driver:
  - `GDRV.sys`
- Dump file:
  - `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp`

### Registry Modifications
- `NoLMHash`
- `DisableRestrictedAdmin`

## 7. Lateral Movement

The attacker moved laterally across systems using built-in Windows utilities.

### Techniques Observed
- LOLBin:
  - `wmic`
- Remote execution command:
  - `cmd.exe /C wmic /node:10[.]10[.]1[.]4 process call create "rundll32 C:\Windows\system32\WowIcmpRemoveReg.dll WowIcmpRemoveReg"`

### User Impersonation
- `CYBERRANGE\roby`

### Beacon Deployment
- `AddressResourcesSpec.dll` deployed to file server

## 8. SQL Server Compromise

The attacker gained access to the SQL Server through brute force.

### Key Findings
- Failed login attempts:
  - `2062`
- Dangerous configuration enabled:
  - `xp_cmdshell`

### Reconnaissance Commands
- `wmic product get name,version`

## 9. Data Exfiltration

Sensitive data was staged and prepared for exfiltration.

### Techniques Observed
- Steganography:
  - Output file: `jvpd2px2at1.bmp`
- Embedded files:
  - `ntoskrnl.exe`
  - `wdigest.dll`
- Registry hive archive:
  - `hiv1.zip`

### SQL Server Data Staging
- Directory:
  - `C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\`

## 10. Ransomware Execution

The final stage involved ransomware deployment across the network.

### Key Indicators
- File extension:
  - `.lsoc`
- Ransom note:
  - `un-lock your files[.]html`

### Defense Disruption
- Shadow copies deleted:
  - `vssadmin.exe Delete Shadows /All /Quiet`

## 11. Impact Assessment

- Enterprise-wide file encryption
- Loss of system availability
- Credential compromise across multiple systems
- Active Directory compromise risk
- Data exfiltration confirmed
- Backup recovery disabled

## 12. Recommendations

- Patch and secure TeamCity servers immediately
- Restrict and monitor PowerShell execution
- Disable or tightly control `wmic` and remote execution tools
- Enforce strong password policies to prevent brute-force attacks
- Disable `xp_cmdshell` unless strictly required
- Monitor and alert on Defender configuration changes
- Implement strict egress filtering (block unauthorized outbound traffic)
- Enable centralized logging and real-time alerting

## 13. Conclusion

This investigation demonstrates a complete attack lifecycle executed by an advanced adversary, from initial access to ransomware deployment. The attacker successfully leveraged vulnerabilities, misconfigurations, and native system tools to evade detection and achieve full network compromise.

Effective detection, rapid response, and improved defensive controls are critical to preventing similar incidents in real-world environments.
