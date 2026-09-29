# Findings Summary – TeamCity APT Ransomware Investigation

**Document Type:** Findings Summary  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Executive Summary

The scenario describes an attack on CyberRange in August 2024 by an advanced persistent threat group, ending in ransomware deployment across the network.
The recorded answers trace initial access through a TeamCity server; defence evasion and a command-and-control tunnel on the beachhead JB01; reconnaissance and credential-dumping attempts on the SQL server and DC01; lateral execution with `wmic`; persistence through scheduled tasks; staging of files for exfiltration; and ransomware encryption.

## Findings by Stage

### 1. Initial Access

- The question states that the attacker used a TeamCity server to gain initial access using CVE-2024-27198.
- Compromised TeamCity URL host: `jb[.]cyberrange[.]cyberdefenders[.]org` (an affected asset)
- Attacker address: `3[.]90[.]168[.]151`; IP lookup returns `ec2-3-90-168-151[.]compute-1[.]amazonaws[.]com`

### 2. Beachhead

- Beachhead host: `JB01` (`10[.]10[.]3[.]4`)
- Downloaded binary: `C:\TeamCity\jre\bin\java64.exe`

### 3. Defence Evasion

- `Set-MpPreference -DisableRealtimeMonitoring $true` in PowerShell script blocks
- Exclusion paths added: `C:\TeamCity`, `C:\Windows`
- MITRE ATT&CK technique: T1562.001 (recorded answer)
- A directory the attacker created, `C:\Windows\temp\1`, was removed with `rmdir /S /Q`

### 4. Command and Control

- Tunnel binary `C:\Program Files\Windows Defender Advanced Threat Protection\Sense.exe` connecting to `3[.]90[.]168[.]151:8443`; the password is recorded but withheld
- Firewall rule allowing inbound TCP on local port 8080

### 5. Reconnaissance

- On the SQL server: PowerView for domain reconnaissance and `wmic product get name,version` for installed software
- Driver enumeration: `Get-WindowsDriver -Online -All`
- Domain-controller queries: `nltest /dclist` and `nltest /dsgetdc`, both shown in the record without a selection

### 6. Persistence

- Scheduled tasks on DC01: `SubmitReporting`, `Scheduled AutoCheck`
- A scheduled task on IT01 runs `rundll32.exe C:\Windows\system32\WowIcmpRemoveReg.dll`

### 7. Credential Access

- `EDRSandblast` with the vulnerable driver `GDRV.sys` against `lsass.exe`
- Dump file on the SQL server: `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp`
- Registry values modified to facilitate credential harvesting: `NoLMHash`, `DisableRestrictedAdmin`
- Invoke-Mimikatz on DC01, run by process 5872

### 8. Lateral Movement

- `wmic /node` execution against four internal addresses, each running a DLL through `rundll32`
- Impersonated account: `CYBERRANGE\roby`
- Beacon copied to FS01: `AddressResourcesSpec.dll`
- Beacon execution on IT01 through `wmic /node` and `rundll32`, reproduced in [Network Analysis](network-analysis.md)

### 9. Exfiltration Staging

- Files embedded into `jvpd2px2at1.bmp` on JB01: `ntoskrnl.exe`, `wdigest.dll`
- Files staged from `C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\` on the SQL server
- Registry hives compressed into `hiv1.zip` on DC01
- No exfiltration transfer is recorded.

### 10. SQL Server Access

- 2,062 failed login attempts before a successful login
- `xp_cmdshell` changed from 0 to 1
- The URL of the binary dropped after access (Q25) is not recorded.

### 11. Privilege-Escalation Tooling and In-Memory Execution

- winPEAS downloaded on the SQL server and saved to `C:\Windows\Temp\peas.exe`
- The question describes Cobalt Strike's execute-assembly running a .NET payload in memory on the SQL server; the recorded technique is T1620, and `rundll32.exe` loads `clrjit.dll`

### 12. Ransomware Execution

- Encryption extension: `.lsoc`
- Ransom note: `un-lock your files[.]html`
- Shadow-copy deletion command: `vssadmin.exe Delete Shadows /All /Quiet`
- The parent process of the encrypting executable (Q37) is not recorded.

## Impact

- Files encrypted with the `.lsoc` extension and ransom notes written
- A shadow-copy deletion command run during the ransomware phase
- Credential-dumping attempts on the SQL server and DC01; their outcome is not recorded
- Files staged for exfiltration; no transfer is recorded
