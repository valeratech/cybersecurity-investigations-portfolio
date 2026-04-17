# Investigation Procedure and Findings – TeamCity APT Ransomware Investigation

**Document Type:** Analysis

## Overview

This document captures the step-by-step investigative workflow, reasoning process, and intermediate findings used to reconstruct the attack lifecycle across the CyberRange environment.

## Investigation Procedure

### Step 1 – Identify Initial Indicators

Initial scoping focused on identifying signs of compromise across the environment.

#### Key Observations
- Files appended with `.lsoc` extension
- Presence of ransom note: `un-lock your files[.]html`
- Spike in PowerShell activity (Event ID 4104)

#### Query Used
`event.code:11 AND file.name:*.*.lsoc`

### Step 2 – Determine Initial Access Vector

Focused on identifying how the attacker entered the environment.

#### Key Observations
- Repeated HTTP requests referencing TeamCity
- Exploitation of CVE-2024-27198
  
#### Query Used
```
event.category:network and network.protocol:http and (
  url.full:(*teamcity* or *jetbrain*) or
  http.request.referrer:(*teamcity* or *jetbrain*)
)
```

#### Finding
- Compromised host: `jb01[.]cyberrange[.]cyberdefenders[.]org`

### Step 3 – Identify Attacker Infrastructure

Pivoted from the beachhead host to external communication.

#### Key Observations
- High-volume outbound traffic to 3[.]90[.]168[.]151
- Reverse DNS resolution to AWS infrastructure

#### Query Used
```
event.category:network and network.protocol:http
and (destination.ip:3.90.168.151 or source.ip:10.10.3.4)
```

#### Finding
- Attacker FQDN: `ec2-3-90-168-151.compute-1.amazonaws[.]com`

### Step 4 – Analyze Defense Evasion Techniques

Focused on identifying how the attacker bypassed security controls.

#### Key Observations
Defender disabled using PowerShell
Exclusion paths added:
- C:\TeamCity
- C:\Windows

#### Query Used
`event.code:4104 AND message:*Set-MpPreference*`

#### Finding
- MITRE Technique: T1562.001 (Impair Defenses)

### Step 5 – Identify Persistence Mechanisms

Examined scheduled tasks and registry modifications.

#### Key Observations
Scheduled tasks created:
- `SubmitReporting`
- `Scheduled AutoCheck`

#### Query Used
`event.code:106 AND host.ip:10.10.0.4` 

#### Finding
- Persistence established on Domain Controller and IT workstation

### Step 6 – Analyze Credential Access

Focused on credential dumping techniques.

#### Key Observations
- Execution of `EDRSandblast.exe`
- Use of vulnerable driver: `GDRV.sys`
- Dump file created:
  - `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp`

#### Query Used
`event.code:4104 AND message:(*downloadstring* OR *Invoke-Expression*)`

#### Finding
- Successful credential dumping via LSASS access

### Step 7 – Trace Lateral Movement

Tracked attacker movement across internal hosts.

#### Key Observations
- Use of `wmic` for remote execution
- User impersonation:
- `CYBERRANGE\roby`

#### Query Used
`process.name:"wmic.exe" AND process.command_line:*process call create*`

#### Finding
- Lateral movement confirmed across multiple hosts

### Step 8 – Investigate Data Exfiltration

Analyzed staging and exfiltration techniques.

#### Key Observations
- Steganography used to embed data into:
  - `jvpd2px2at1.bmp`
- Files embedded:
  - `ntoskrnl.exe`
  - `wdigest.dll`

#### Query Used
`event.code:4104 AND message:(Compress-Archive OR ConvertTo-SecureString)`

Finding
- Data prepared for covert exfiltration

### Step 9 – Analyze Ransomware Execution

Final stage of the attack lifecycle.

#### Key Observations
- File encryption extension:
  - `.lsoc`
- Shadow copies deleted using:
  - `vssadmin.exe Delete Shadows /All /Quiet`

#### Query Used
`event.code:11 AND file.name:*.*.lsoc`

#### Finding
Widespread ransomware execution confirmed

## Summary of Findings
- Initial access via TeamCity exploitation
- Rapid establishment of persistence and C2
- Credential dumping and privilege escalation achieved
- Lateral movement across infrastructure
- Data exfiltration using steganography
- Final ransomware deployment causing enterprise-wide impact

## Notes
- All analysis performed using centralized Elastic logs
- Evidence remained unmodified
- All timestamps normalized to UTC
- All indicators defanged
