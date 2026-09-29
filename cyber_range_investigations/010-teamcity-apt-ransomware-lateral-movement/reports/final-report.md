# Final Investigation Report – TeamCity APT Ransomware

**Document Type:** Final Report  
**Case Title:** TeamCity APT Ransomware – Lateral Movement & Data Exfiltration  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Documentation Started:** 2026-04-16  
**Documentation Last Updated:** 2026-09-28  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

The scenario describes an attack on CyberRange in August 2024 by an advanced persistent threat group, ending in ransomware deployment across the network.
The recorded answers show initial access through the TeamCity service `jb[.]cyberrange[.]cyberdefenders[.]org` and a beachhead on `JB01`, followed by defence evasion, a command-and-control tunnel, reconnaissance and credential-dumping attempts, `wmic /node` execution against four internal addresses, scheduled-task persistence, staging of files for exfiltration, and encryption with the `.lsoc` extension.
Impact is stated as recorded actions; outcomes the record does not show are not asserted.

## 2. Scope and Objectives

### Scope

- The provided Elastic instance, with pre-parsed logs from the compromised systems
- Hosts named in the record: JB01 in the DMZ; the SQL server, DC01, FS01 and IT01; and one further internal address

### Objectives

- Identify the initial access vector
- Trace attacker activity across the hosts named in the record
- Document persistence, credential access and lateral movement
- Document exfiltration staging and ransomware execution
- Record indicators and affected assets with their basis

## 3. Initial Access

The question states that the attacker used a TeamCity server to gain initial access using CVE-2024-27198.
- Compromised TeamCity URL host: `jb[.]cyberrange[.]cyberdefenders[.]org`
- Beachhead host: `JB01` (`jb01[.]cyberrange[.]cyberdefenders[.]org`, `10[.]10[.]3[.]4`)
- Attacker address: `3[.]90[.]168[.]151`; IP lookup returns `ec2-3-90-168-151[.]compute-1[.]amazonaws[.]com`

## 4. Defence Evasion

- `Set-MpPreference -DisableRealtimeMonitoring $true` in PowerShell script blocks on JB01
- Exclusion paths added: `C:\TeamCity`, `C:\Windows`
- Firewall rule allowing inbound TCP on local port 8080
- `C:\Windows\temp\1` removed with `rmdir /S /Q`
- MITRE ATT&CK: T1562.001 (recorded answer)

## 5. Command and Control

The tunnel binary `C:\Program Files\Windows Defender Advanced Threat Protection\Sense.exe` ran on JB01 with `-connect` to `3[.]90[.]168[.]151:8443`. The password it used is recorded but withheld from this case.
The attacker downloaded `java64.exe` from the attacker address to `C:\TeamCity\jre\bin\java64.exe` and started it.

## 6. Persistence

- Scheduled tasks on DC01: `SubmitReporting`, `Scheduled AutoCheck`
- A scheduled task on IT01 running `WowIcmpRemoveReg.dll` through `rundll32.exe`

## 7. Credential Access

- `EDRSandblast` with the vulnerable driver `GDRV.sys` against `lsass.exe`; dump file `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp` on the SQL server
- Registry values modified to facilitate credential harvesting: `NoLMHash`, `DisableRestrictedAdmin`
- Invoke-Mimikatz on DC01, run by process 5872
Whether any credential was obtained is not recorded.

## 8. Lateral Movement

`wmic /node` execution from `cmd.exe` reached `10[.]10[.]0[.]4`, `10[.]10[.]0[.]5`, `10[.]10[.]0[.]7` and `10[.]10[.]1[.]4`, each running a DLL through `rundll32`.
- Impersonated account: `CYBERRANGE\roby`
- Beacon copied to FS01: `AddressResourcesSpec.dll`
- Recorded command for IT01:

```text
C:\Windows\system32\cmd.exe /C wmic /node:10.10.1.4 process call create "rundll32 C:\Windows\system32\WowIcmpRemoveReg.dll WowIcmpRemoveReg"
```

## 9. SQL Server Access

- 2,062 failed login attempts before a successful login
- `xp_cmdshell` changed from 0 to 1
- Installed software listed with `wmic product get name,version`
- winPEAS downloaded and saved to `C:\Windows\Temp\peas.exe`
- In-memory execution: the question describes Cobalt Strike's execute-assembly; the recorded technique is T1620

## 10. Exfiltration Staging

- Files embedded into `jvpd2px2at1.bmp` on JB01: `ntoskrnl.exe`, `wdigest.dll`
- Files staged from `C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\` on the SQL server
- Registry hives compressed into `hiv1.zip` on DC01
No exfiltration transfer is recorded.

## 11. Ransomware Execution

- Encryption extension: `.lsoc`
- Ransom note: `un-lock your files[.]html`
- Shadow-copy deletion command: `vssadmin.exe Delete Shadows /All /Quiet`

## 12. Impact Assessment

- Files encrypted and ransom notes written
- A shadow-copy deletion command run during the ransomware phase
- Credential-dumping attempts on the SQL server and DC01; their outcome is not recorded
- Files staged for exfiltration; no transfer is recorded

## 13. Recommendations

- Patch TeamCity servers against CVE-2024-27198 and restrict their exposure
- Alert on encoded PowerShell and on Defender configuration changes
- Restrict and monitor remote execution with `wmic`
- Enforce strong SQL Server authentication and keep `xp_cmdshell` disabled
- Restrict outbound connections from DMZ hosts
- Protect LSASS and block known vulnerable drivers

## 14. Limitations

- Times are recorded for a subset of events only; see the [Timeline](../analysis/timeline-utc.md).
- The Q25 download URL and the Q37 parent process are not recorded; the Q15 screenshot shows two commands without a selection.
- Outcomes such as credential exposure, exfiltration and recovery impact are not recorded, so none is asserted.
- The Q9 tunnel password is recorded but withheld from this case.

## 15. Conclusion

The recorded activity runs from initial access on JB01 to ransomware encryption, with actions on the SQL server, DC01, FS01 and IT01.
**Analyst inference.** Alerting on encoded PowerShell, Defender configuration changes and remote `wmic` execution would have exposed several recorded stages of this activity.

## Related Documents

- [Case Overview](../README.md)
- [Timeline](../analysis/timeline-utc.md)
- [Indicators of Compromise](../iocs/network-iocs.md)
- [Evidence Inventory](../evidence-metadata/evidence-inventory.md)
