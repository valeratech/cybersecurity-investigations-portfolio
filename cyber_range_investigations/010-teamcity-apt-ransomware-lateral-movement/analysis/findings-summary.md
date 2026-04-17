# Findings Summary – TeamCity APT Ransomware Investigation

**Document Type:** Findings

## Executive Summary

This investigation confirms a full-scope advanced persistent threat (APT) intrusion resulting in enterprise-wide ransomware deployment within the CyberRange environment.

The attacker successfully achieved initial access through exploitation of a vulnerable TeamCity server, established persistence, conducted extensive reconnaissance, moved laterally across multiple systems, performed credential harvesting, and executed ransomware across the network.

## Confirmed Attack Flow

### 1. Initial Access
- Exploited TeamCity vulnerability (CVE-2024-27198)
- Compromised TeamCity server:
  - `jb01[.]cyberrange[.]cyberdefenders[.]org`
- Attacker source:
  - IP: `3[.]90[.]168[.]151`
  - FQDN: `ec2-3-90-168-151.compute-1.amazonaws[.]com`

### 2. Beachhead Establishment
- Initial compromised host:
  - `JB01 (10[.]10[.]3[.]4)`
- Malware staged in:
  - `C:\TeamCity\jre\bin\java64.exe`

### 3. Defense Evasion
- Disabled Microsoft Defender:
  - `Set-MpPreference -DisableRealtimeMonitoring $true`
- Added exclusion paths:
  - `C:\TeamCity`
  - `C:\Windows`
- MITRE Technique:
  - T1562.001 – Impair Defenses

### 4. Command and Control (C2)
- Established tunneling communication
- Firewall rule created:
  - Port: `8080`
- C2 traffic tunneled to attacker-controlled infrastructure

### 5. Persistence
- Scheduled tasks created on Domain Controller:
  - `SubmitReporting`
  - `Scheduled AutoCheck`
- Additional persistence on IT workstation via scheduled tasks

### 6. Credential Access
- LSASS credential dumping via:
  - Tool: `EDRSandblast`
  - Vulnerable driver: `GDRV.sys`
- Dump file created:
  - `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp`
- Registry modifications:
  - `NoLMHash`
  - `DisableRestrictedAdmin`

### 7. Reconnaissance
- System enumeration commands:
  - `Get-WindowsDriver -Online -All`
  - `wmic product get name,version`
- Active Directory reconnaissance:
  - Tool: PowerView

### 8. Lateral Movement
- Remote execution via LOLBin:
  - `wmic`
- User impersonation:
  - `CYBERRANGE\roby`
- Beacon deployment:
  - `AddressResourcesSpec.dll` (File Server)
- Remote execution command:
  - `cmd.exe /C wmic /node:10[.]10[.]1[.]4 process call create "rundll32 C:\Windows\system32\WowIcmpRemoveReg.dll WowIcmpRemoveReg"`

### 9. Data Exfiltration
- Steganography used to embed encrypted data into:
  - `jvpd2px2at1.bmp`
- Embedded files:
  - `ntoskrnl.exe`
  - `wdigest.dll`
- SQL Server data staged from:
  - `C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\`
- Registry hives compressed:
  - `hiv1.zip`

### 10. SQL Server Compromise
- Brute force attempts:
  - `2062` failed login attempts
- Dangerous configuration enabled:
  - `xp_cmdshell`
- Additional malware deployment via remote download

### 11. Privilege Escalation
- Tool used:
  - `winPEASx64_ofs.exe`
- Execution method:
  - Reflective code loading (T1620)

### 12. Ransomware Execution
- File encryption extension:
  - `.lsoc`
- Ransom note:
  - `un-lock your files[.]html`
- Shadow copies deleted:
  - `vssadmin.exe Delete Shadows /All /Quiet`

## Impact Assessment

- Full network compromise across DMZ, Infrastructure, and Workstations
- Domain-level credential exposure
- SQL Server compromise and data staging
- Data exfiltration via covert techniques
- Enterprise-wide ransomware deployment
- Loss of system recoverability due to shadow copy deletion

## Confidence Level

High – Findings are supported by correlated log evidence across Sysmon, PowerShell, Task Scheduler, MSSQL, and network telemetry.
