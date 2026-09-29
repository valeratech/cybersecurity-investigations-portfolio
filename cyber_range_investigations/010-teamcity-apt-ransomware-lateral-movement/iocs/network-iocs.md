# Network Indicators of Compromise – TeamCity APT Ransomware Investigation

**Document Type:** IOC Collection  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Overview

Entries are grouped by role: attacker-side indicators, affected assets, and contextual observables that are not indicators. Each entry cites its record basis. Indicators are defanged.

## Malicious Indicators

| Indicator | Type | Basis |
|---|---|---|
| `3[.]90[.]168[.]151` | Attacker IP address | Q5 answer |
| `3[.]90[.]168[.]151:8443` | Tunnel endpoint | Q9 screenshot |
| `ec2-3-90-168-151[.]compute-1[.]amazonaws[.]com` | Reverse-DNS name of the attacker address | Q6 answer (IP lookup) |
| `http[:]//3[.]90[.]168[.]151:80/java64[.]exe` | Download URL | Q13 decoded command |
| `C:\TeamCity\jre\bin\java64.exe` | Downloaded binary | Q13 answer |
| `C:\Program Files\Windows Defender Advanced Threat Protection\Sense.exe` | Tunnel binary | Q9 screenshot |
| `C:\Windows\Temp\smss64.exe` | Parent of reconnaissance and lateral-movement commands | Q15, Q32 and Q35 screenshots |
| `C:\Windows\Temp\peas.exe` | Local copy of the downloaded winPEAS | Q27 decoded command |
| `C:\Windows\Temp\EDRSandblast.exe` | Credential-dumping tool | Q29 answer and decoded command |
| `C:\Windows\Temp\GDRV.sys` | Vulnerable driver | Q30 answer and decoded command |
| `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp` | Dump file | Q31 answer |
| `AclNumsInvertHost.dll`, `PerformanceCaptionApi.dll`, `AddressResourcesSpec.dll`, `WowIcmpRemoveReg.dll` | DLLs run by `rundll32` through `wmic /node` | Q12 screenshot; Q35 and Q36 answers |
| `jvpd2px2at1.bmp` | Steganography output file | Q19 answer |
| `hiv1.zip` | Registry-hive archive on DC01 | Q22 answer |
| `un-lock your files[.]html` | Ransom note | Q2 answer |
| `.lsoc` | Encryption extension | Q1 answer |
| `SubmitReporting`, `Scheduled AutoCheck` | Scheduled tasks on DC01 | Q17 answer |
| `NoLMHash`, `DisableRestrictedAdmin` | Registry values modified to facilitate credential harvesting | Q32 question and answer |

## Attacker Commands

| Command | Basis |
|---|---|
| `vssadmin.exe Delete Shadows /All /Quiet` | Q38 answer |
| `C:\Windows\system32\cmd.exe /C rmdir /S /Q C:\Windows\temp\1` | Q11 screenshot |
| `C:\Windows\system32\cmd.exe /C nltest /dclist:cyberrange.cyberdefenders.org` | Q15 screenshot |
| `C:\Windows\system32\cmd.exe /C nltest /dsgetdc:cyberrange.cyberdefenders.org` | Q15 screenshot |
| `wmic product get name,version` | Q26 answer |
| `Get-WindowsDriver -Online -All` | Q14 answer |
| `New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080` | Q10 decoded command |

## Affected Assets

| Asset | Role | Basis |
|---|---|---|
| `jb[.]cyberrange[.]cyberdefenders[.]org` | Compromised TeamCity service (initial access) | Q3 question and answer |
| `JB01` (`jb01[.]cyberrange[.]cyberdefenders[.]org`, `10[.]10[.]3[.]4`) | Beachhead host | Q4 answer and notes; network diagram |
| SQL server `10[.]10[.]0[.]6` | Brute-forced, reconfigured and used for credential dumping | Q23 to Q31 |
| DC01 `10[.]10[.]0[.]4` | Scheduled tasks, Invoke-Mimikatz and the registry-hive archive | Q17, Q22 and Q33 |
| FS01 `10[.]10[.]0[.]7` | Received `AddressResourcesSpec.dll` | Q35 |
| IT01 `10[.]10[.]1[.]4` | Scheduled task and `WowIcmpRemoveReg.dll` | Q18 and Q36 |
| `10[.]10[.]0[.]5` | `wmic /node` target running `PerformanceCaptionApi.dll`; hostname not recorded | Q12 screenshot |
| `CYBERRANGE\roby` | Account impersonated for lateral movement | Q34 question and answer |
| `cyberrange[.]cyberdefenders[.]org` | The organisation's domain | Q15 screenshot |

## Contextual Observables — Not IOCs

| Observable | Context | Basis |
|---|---|---|
| `https[:]//github[.]com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64_ofs[.]exe` | Public release URL of winPEAS, the tool the attacker downloaded | Q27 answer and decoded command |
| `https[:]//raw[.]githubusercontent[.]com/g4uss47/Invoke-Mimikatz/master/Invoke-Mimikatz[.]ps1` | Public script URL fetched on DC01 | Q33 decoded command |
| `SpeechModelInstallTask`, `StartupAppTaskCheck` | Task names searched in the Q18 hint and queries | Q18 hint and queries |

## Notes

- Each entry cites the question, answer or screenshot it rests on; no validation beyond that record is claimed.
- Recorded commands that contain addresses appear exactly, inside code blocks, in the analysis documents.
- The Q9 tunnel password is recorded but withheld; see the [Evidence Inventory](../evidence-metadata/evidence-inventory.md).
