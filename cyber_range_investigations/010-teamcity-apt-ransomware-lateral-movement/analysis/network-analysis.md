# Network Analysis – TeamCity APT Ransomware Investigation

**Document Type:** Analysis  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Objective

Describe the network-related activity recorded for this case: initial access, attacker infrastructure, tool transfer, command and control, lateral movement and exfiltration staging.

## Data Sources

- HTTP data in the `nginx_rp` data view (`http.request.referrer`, `url.full`)
- Sysmon process-creation command lines (Event ID 1)
- PowerShell script blocks (Event ID 4104) and decoded encoded commands

## 1. Initial Access – TeamCity

HTTP data behind the NGINX reverse proxy shows referrers and URLs on the TeamCity service: 515 referrer records and 16 `url.full` records.
The question states that the attacker gained initial access through a TeamCity server using CVE-2024-27198; the recorded answer for the compromised TeamCity URL is `jb[.]cyberrange[.]cyberdefenders[.]org`.
The beachhead host is `JB01` at `10[.]10[.]3[.]4`; the recorded network-diagram excerpt shows it in the DMZ with the WAF (NGINX) at `10[.]10[.]3[.]6`.
The recorded query is in [Analysis Tools and Methods](../case-notes/analysis-tools-and-methods.md).

## 2. Attacker Infrastructure

The attacker address is `3[.]90[.]168[.]151` (Q5 answer). The range hint describes it as the address accounting for about 78% of non-internal traffic with the beachhead.
IP lookup returns `ec2-3-90-168-151[.]compute-1[.]amazonaws[.]com` for this address (Q6).
**Analyst inference.** The EC2 name indicates infrastructure hosted by Amazon Web Services.

## 3. Tool Transfer After Initial Access

The recorded downloads come from decoded PowerShell commands, not from network-log results.
- JB01: `java64.exe` from the attacker address, saved to `C:\TeamCity\jre\bin\java64.exe` and started (Q13). The question places the download after the attacker evaded defences.
- SQL server: winPEAS from its public release URL, saved to `C:\Windows\Temp\peas.exe` (Q27).
- DC01: the Invoke-Mimikatz script from a public URL, run in memory (Q33).
The decoded commands are reproduced in [Analysis Tools and Methods](../case-notes/analysis-tools-and-methods.md).

## 4. Command and Control

The tunnel binary `C:\Program Files\Windows Defender Advanced Threat Protection\Sense.exe` ran on JB01 with `-connect` to `3[.]90[.]168[.]151:8443` and a password argument (Q9). The password is recorded but withheld from this case.
A firewall rule allows inbound TCP on local port 8080 (Q10, decoded command). The question describes the rule as facilitating communication with the command-and-control server.

## 5. Lateral Movement

Remote execution used `wmic /node` from `cmd.exe` against four internal addresses. Each target received a `Set-MpPreference -DisableRealtimeMonitoring $true` command and a DLL run by `rundll32` (Q12).

| Target | DLL run by `rundll32` | Basis |
|---|---|---|
| `10[.]10[.]0[.]4` (DC01) | `AclNumsInvertHost.dll` | Q12 screenshot; Q17 query |
| `10[.]10[.]0[.]5` (hostname not recorded) | `PerformanceCaptionApi.dll` | Q12 screenshot |
| `10[.]10[.]0[.]7` (FS01) | `AddressResourcesSpec.dll` | Q12 screenshot; Q35 answer |
| `10[.]10[.]1[.]4` (IT01) | `WowIcmpRemoveReg.dll` | Q12 screenshot; Q36 answer |

The recorded command for IT01 (Q36):

```text
C:\Windows\system32\cmd.exe /C wmic /node:10.10.1.4 process call create "rundll32 C:\Windows\system32\WowIcmpRemoveReg.dll WowIcmpRemoveReg"
```

The account `CYBERRANGE\roby` was impersonated during lateral movement (Q34).

## 6. Exfiltration Staging

Files were embedded into `jvpd2px2at1.bmp` on JB01 (Q19); files from `C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\` on the SQL server were compressed into a .zip file (Q21); registry hives were compressed into `hiv1.zip` on DC01 (Q22). Each question describes this as preparation for exfiltration.
The record shows the staging; it does not record a transfer.

## 7. Ransomware

Encrypted files carry the `.lsoc` extension, and ransom notes are named `un-lock your files[.]html` (Q1, Q2).

## Summary

- Initial access through the TeamCity service, per the question's CVE-2024-27198 premise
- Tools transferred after initial access by decoded PowerShell download commands
- A tunnel to `3[.]90[.]168[.]151:8443` and an inbound firewall rule for TCP 8080
- Lateral execution with `wmic /node` against four internal addresses
- Files staged for exfiltration on JB01, the SQL server and DC01
- Ransomware encryption with the `.lsoc` extension
