# Investigation Procedure and Findings – TeamCity APT Ransomware Investigation

**Document Type:** Analysis  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Overview

This document follows the question set in order of investigation stage. Each finding cites its question, and each recorded query is reproduced once, in the analysis tools document.

## Investigation Procedure

### Step 1 – Ransomware Indicators (Q1, Q2)

File-creation events and field statistics identify the encryption marker and the ransom note.

#### Findings

- Encryption extension `.lsoc`
- Ransom note `un-lock your files[.]html`, 24 records across three user profiles

Recorded queries: Q1, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

### Step 2 – Initial Access and Beachhead (Q3, Q4)

HTTP data behind the NGINX reverse proxy shows the TeamCity service; the network-diagram excerpt places the beachhead in the DMZ.

#### Findings

- The question states initial access through a TeamCity server using CVE-2024-27198
- Compromised TeamCity URL host: `jb[.]cyberrange[.]cyberdefenders[.]org`
- Beachhead host: `JB01` (`10[.]10[.]3[.]4`)

Recorded queries: Q3, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

### Step 3 – Attacker Infrastructure (Q5, Q6)

The range hint points to the external address that accounts for most non-internal traffic with the beachhead.

#### Findings

- Attacker address: `3[.]90[.]168[.]151`
- IP lookup: `ec2-3-90-168-151[.]compute-1[.]amazonaws[.]com`

### Step 4 – Defence Evasion (Q7, Q8, Q10, Q11)

PowerShell script blocks and decoded commands show changes to Defender and the firewall, and cleanup.

#### Findings

- `Set-MpPreference` disabled real-time monitoring and added exclusions `C:\TeamCity` and `C:\Windows`; technique T1562.001
- Firewall rule allowing inbound TCP on local port 8080
- `C:\Windows\temp\1` removed with `rmdir /S /Q`

Recorded queries: Q7, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

### Step 5 – Command and Control and Tool Transfer (Q9, Q13)

Process command lines on JB01 and a decoded download command show the tunnel binary and the downloaded executable.

#### Findings

- Tunnel binary `C:\Program Files\Windows Defender Advanced Threat Protection\Sense.exe` connecting to `3[.]90[.]168[.]151:8443`; the password is recorded but withheld
- `java64.exe` downloaded from the attacker address and saved to `C:\TeamCity\jre\bin\java64.exe`

Recorded queries: Q9, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

### Step 6 – Reconnaissance (Q14, Q15, Q16, Q26)

Decoded commands and command-line statistics show enumeration of drivers, domain controllers, the domain and installed software.

#### Findings

- `Get-WindowsDriver -Online -All`
- `nltest /dclist` and `nltest /dsgetdc` against the domain, from a `smss64.exe` parent; the record shows both without a selection
- PowerView on the SQL server; `wmic product get name,version` on the SQL server

### Step 7 – Persistence (Q17, Q18)

Task Scheduler and Security events show scheduled tasks on DC01 and IT01.

#### Findings

- DC01 tasks: `SubmitReporting`, `Scheduled AutoCheck`
- IT01 task action: `rundll32.exe C:\Windows\system32\WowIcmpRemoveReg.dll`

Recorded queries: Q17, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

### Step 8 – SQL Server Access (Q23, Q24, Q25)

MSSQL events on the SQL server show the brute force and a configuration change.

#### Findings

- 2,062 failed logins (Event ID 18456) before a successful login
- `xp_cmdshell` changed from 0 to 1 (Event ID 15457)
- The URL of the binary dropped after access is not recorded (Q25)

Recorded queries: Q23, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

### Step 9 – Privilege-Escalation Tooling and In-Memory Execution (Q27, Q28)

A decoded download command and Sysmon image-load events on the SQL server.

#### Findings

- winPEAS saved to `C:\Windows\Temp\peas.exe`
- Technique T1620 for Cobalt Strike's execute-assembly, per the question; `rundll32.exe` loads `clrjit.dll`

Recorded queries: Q28, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

### Step 10 – Credential Access (Q29 to Q33)

Decoded PowerShell commands and Sysmon process events.

#### Findings

- `EDRSandblast` with `GDRV.sys` against `lsass.exe`; dump file `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp`
- Registry values `NoLMHash`, `DisableRestrictedAdmin`
- Invoke-Mimikatz on DC01, process 5872
- Whether any credential was obtained is not recorded

### Step 11 – Lateral Movement (Q12, Q34, Q35, Q36)

Process command lines show `wmic /node` execution against internal addresses.

#### Findings

- `wmic /node` against `10[.]10[.]0[.]4`, `10[.]10[.]0[.]5`, `10[.]10[.]0[.]7` and `10[.]10[.]1[.]4`, each running a DLL through `rundll32`
- Impersonated account `CYBERRANGE\roby`; beacon `AddressResourcesSpec.dll` on FS01

Recorded queries: Q12, Q35, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

### Step 12 – Exfiltration Staging (Q19 to Q22)

PowerShell script blocks show files embedded and compressed for exfiltration.

#### Findings

- `jvpd2px2at1.bmp` on JB01, embedding `ntoskrnl.exe` and `wdigest.dll`
- Files from `C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\` on the SQL server; registry hives in `hiv1.zip` on DC01
- No exfiltration transfer is recorded

### Step 13 – Ransomware Execution (Q37, Q38)

File-creation and process events from the ransomware phase.

#### Findings

- Shadow-copy deletion command `vssadmin.exe Delete Shadows /All /Quiet`
- The parent process of the encrypting executable is not recorded (Q37)

Recorded queries: Q37, in [Analysis Tools and Methods](analysis-tools-and-methods.md).

## Summary of Findings

- Initial access through the TeamCity service, per the question set
- Defence evasion and a command-and-control tunnel on JB01
- Reconnaissance, brute force and credential-dumping attempts on the SQL server; Invoke-Mimikatz on DC01
- Scheduled-task persistence on DC01 and IT01
- Lateral execution with `wmic /node`
- Files staged for exfiltration; ransomware encryption with `.lsoc`

## Notes

- Queries appear once, exactly as recorded, in the analysis tools document.
- Answers not recorded: Q25 and Q37. Q11, Q15 and Q18 are answered in screenshots only; Q15's screenshot shows two commands without a selection.
