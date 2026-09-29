# Timeline – TeamCity APT Ransomware Investigation

**Document Type:** Timeline  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Evidence Basis

Times are shown as recorded: display times from Kibana Discover rows and screenshots, `UtcTime` values inside Sysmon events, values written in the analyst's notes, and time windows from range hints.
Displayed times are UTC: in two Sysmon events the displayed `@timestamp` equals the event's `UtcTime` (04:31:14.890 in the Q28 screenshot; 05:45:36.808 in the Q35 screenshot).
Only events with a recorded time appear in the first table. Events without a recorded time are listed separately, without order.

## Timestamped Observations

| Recorded time (UTC) | Time class | Event | Source | Label |
|---|---|---|---|---|
| 2024-08-19 12:58:19.669 | Value in the analyst's notes | Recorded under "Ransome Note" (second pair); the notes do not say which event it belongs to | Q5 notes | Observed |
| 2024-08-20 03:54:00.515 to 04:11:59.482 | Discover display times | PowerShell command lines listed for the Q13 search, including encoded commands | Q13 screenshot | Observed |
| 2024-08-20 03:55:13.671 | Value in the analyst's notes | Recorded under "Ransome Note" (second pair) | Q5 notes | Observed |
| 2024-08-20 03:55:36.851 | Discover display time | Encoded command whose decoded form downloads `java64.exe` from `3[.]90[.]168[.]151` to `C:\TeamCity\jre\bin\java64.exe` and starts it | Q13 screenshots | Observed |
| 2024-08-20 04:05:57 (±10 minutes) | Search window in the analyst's notes | Window the analyst used to search host `10[.]10[.]3[.]4` for the steganography script (Q19); a search window, not an event time | Q19 notes | Observed |
| 2024-08-20 04:21:08 (around) | Range hint | Failed MSSQL logins cluster around this time (Q23) | Q23 hint | Range-supplied |
| 2024-08-20 04:31:14.890 | Sysmon `UtcTime`, equal to the display time | `rundll32.exe` loads `clrjit.dll` on the SQL server (Q28) | Q28 query and screenshot | Observed |
| 2024-08-20 04:43:12.810 | Discover display time | Encoded PowerShell whose decoded form is `Get-WindowsDriver -Online -All` (Q14) | Q14 screenshots | Observed |
| 2024-08-20 05:33:09.424 | Sysmon `UtcTime` | PowerShell process 5872 runs an encoded command on DC01; decoded, it loads and runs Invoke-Mimikatz (Q33) | Q33 question, answer and screenshots | Range-supplied; Range-accepted; Observed |
| 2024-08-20 05:33:45.709 | Sysmon `UtcTime` | A process is created as `CYBERRANGE\roby`, with a parent `rundll32` running `AclNumsInvertHost.dll` (Q34) | Q34 screenshot | Observed |
| 2024-08-20 05:45:36.808 | Sysmon `UtcTime`, equal to the display time | `cmd.exe` runs `wmic /node:10[.]10[.]0[.]7` to start `rundll32` with `AddressResourcesSpec.dll`; parent `smss64.exe` (Q35) | Q35 notes and screenshot | Observed |
| 2024-08-20 06:35:00.000 to 06:46:00.000 | Time-picker window | Window the analyst searched for Q5; a search window, not an event time | Q5 screenshot | Observed |
| 2024-08-20 06:35:58.428 and 06:40:42.650 | Values in the analyst's notes | Recorded under "Encryption .lsoc Ransomware" | Q5 notes | Observed |
| 2024-08-20 06:36:04.423 and 06:45:51.584 | Values in the analyst's notes | Recorded under "Ransome Note" (first pair) | Q5 notes | Observed |
| 2024-08-20 06:40 to 06:45 | Range hint | Window in which to look for the ransom-note HTML files (Q2) | Q2 hint | Range-supplied |
| 2024-08-20 06:43:26.053 | Discover display time | Encoded command that downloads `winPEASx64_ofs.exe` to `C:\Windows\Temp\peas.exe` (Q27) | Q27 screenshots | Observed |

## Established Events Without Recorded Times

Listed by question, not in time order.

| Event | Source | Label |
|---|---|---|
| Initial access through the TeamCity service `jb[.]cyberrange[.]cyberdefenders[.]org`; the question states CVE-2024-27198 | Q3 question and answer | Range-supplied; Range-accepted |
| Beachhead host `JB01` | Q4 answer | Range-accepted |
| Defender real-time monitoring disabled; exclusions `C:\TeamCity` and `C:\Windows` added; the range hint places this before the malware download | Q7 and Q8 answers, Q7 hint and screenshot | Range-accepted; Range-supplied; Observed |
| Inbound firewall rule allowing TCP 8080 | Q10 answer and decoded command | Range-accepted; Observed |
| Tunnel binary `C:\Program Files\Windows Defender Advanced Threat Protection\Sense.exe` run with `-connect` to `3[.]90[.]168[.]151:8443` and a password argument | Q9 screenshot | Observed |
| `C:\Windows\temp\1` removed with `rmdir /S /Q` | Q11 screenshot | Observed |
| Domain-controller queries with `nltest /dclist` and `nltest /dsgetdc`, with `smss64.exe` as the parent command line | Q15 screenshots | Observed |
| Domain reconnaissance with PowerView and driver enumeration with `Get-WindowsDriver -Online -All`; installed software listed with `wmic product get name,version` on the SQL server | Q14, Q16 and Q26 | Range-supplied; Range-accepted |
| Scheduled tasks `SubmitReporting` and `Scheduled AutoCheck` on DC01; a task on IT01 runs `WowIcmpRemoveReg.dll` through `rundll32.exe` | Q17 answer; Q18 screenshot | Range-accepted; Observed |
| Files embedded into `jvpd2px2at1.bmp` on JB01 (`ntoskrnl.exe`, `wdigest.dll`) for exfiltration | Q19 and Q20 | Range-supplied; Range-accepted |
| Files staged from `C:\Program Files\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQL\Binn\` on the SQL server; registry hives compressed into `hiv1.zip` on DC01 | Q21 and Q22 | Range-supplied; Range-accepted |
| 2,062 failed MSSQL logins before a successful login; `xp_cmdshell` changed from 0 to 1 | Q23 and Q24 | Range-accepted; Range-supplied; Observed |
| `EDRSandblast` with the `GDRV.sys` driver against `lsass.exe`; dump file `MpCmdRun-38-53C9D589-6B66-4F30-9BAB-9A0193B0BAFC.dmp` created on the SQL server, then compressed and deleted | Q29 to Q31 answers and decoded commands | Range-accepted; Range-supplied; Observed |
| Registry values `NoLMHash` and `DisableRestrictedAdmin` modified | Q32 answer and screenshot | Range-accepted; Observed |
| `wmic /node` execution against four internal addresses, each receiving a `Set-MpPreference -DisableRealtimeMonitoring $true` command and a `rundll32` beacon | Q12 answer and screenshot | Range-accepted; Observed |
| Shadow-copy deletion command `vssadmin.exe Delete Shadows /All /Quiet` | Q38 answer and screenshot | Range-accepted; Observed |

## Limitations

- Times are recorded only for the events in the first table; other events are listed without order.
- The notes record the Q5 value pairs without saying which event each value belongs to.
- The Q25 download URL and the Q37 parent process are not recorded; the Q15 screenshot shows two `nltest` commands without a selection.
- The Q2 and Q23 time windows come from range hints and are shown as range-supplied.
