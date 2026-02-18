# Hunt Queries (Splunk + Elastic)

**Case ID:** 005  
**Case Title:** Disk Forensics — Telegram download of Covenant + mimikatz masquerade + persistence  
**Time Standard:** UTC  
**Scope:** Queries aligned to observed artifacts (new user, scheduled task, service persistence, suspicious execution from Downloads, credential access attempts).

## Assumptions / Notes

- Field names vary by environment. These queries include common variants.
- Prefer Sysmon where available for richer process visibility.
- Where possible, constrain to the incident window around 2022-11-11 (UTC).

Defanged indicators used in this case:
- Host: MAGENTA (domain: polo[.]shirts[.]corp)
- Host IP: 10[.]10[.]5[.]113
- Remote share host: 10[.]10[.]5[.]86
- New user: cpitter
- Service: cleanup-schedule
- Scheduled task: \spawn
- Files: Minecraft.exe (Covenant), mimikatz.exe masqueraded as svchost.exe
- Targeted file: Credentials.txt
- Remote file: lansweeper.ps1

# Splunk (SPL)

## A) New local/domain user created (Security 4720)
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4720
| stats count min(_time) as firstSeen max(_time) as lastSeen values(SubjectUserName) as subject values(TargetUserName) as newUser values(TargetDomainName) as domain by host
| sort - lastSeen

### Pivot: specifically for cpitter
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4720 (TargetUserName="cpitter" OR SamAccountName="cpitter")
| table _time host SubjectUserName TargetDomainName TargetUserName SamAccountName Message

## B) Scheduled task created/modified (Security 4698 / 4702)
index=wineventlog sourcetype="WinEventLog:Security" (EventCode=4698 OR EventCode=4702)
| eval taskName=coalesce(TaskName, Task_Name)
| search taskName="\\spawn" OR like(Message,"%\\spawn%")
| table _time host user taskName Message

### If Microsoft-Windows-TaskScheduler/Operational is ingested
index=wineventlog (sourcetype="WinEventLog:Microsoft-Windows-TaskScheduler/Operational" OR channel="Microsoft-Windows-TaskScheduler/Operational")
| search ("\\spawn" OR "spawn")
| table _time host EventCode Message

## C) Service installed (System 7045)
index=wineventlog sourcetype="WinEventLog:System" EventCode=7045
| eval svc=coalesce(ServiceName, service_name)
| search svc="cleanup-schedule" OR like(Message,"%cleanup-schedule%")
| table _time host svc ImagePath ServiceType StartType AccountName Message

### Broader: suspicious services with binaries in user-writable paths
index=wineventlog sourcetype="WinEventLog:System" EventCode=7045
| eval img=coalesce(ImagePath, ServiceFileName)
| search img="*\\Users\\*" OR img="*\\Downloads\\*" OR img="*\\AppData\\*"
| table _time host ServiceName img AccountName Message

## D) Suspicious process execution from Downloads (Sysmon EID 1)
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval img=coalesce(Image,ProcessPath,NewProcessName)
| search img="*\\Downloads\\*" AND (img="*svchost.exe" OR img="*Minecraft.exe" OR img="*mimikatz.exe")
| table _time host User img CommandLine ParentImage ParentCommandLine ProcessId ParentProcessId

### Generic: any svchost.exe outside System32/SysWOW64
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| eval img=coalesce(Image,NewProcessName)
| search img="*\\svchost.exe" NOT (img="C:\\Windows\\System32\\svchost.exe" OR img="C:\\Windows\\SysWOW64\\svchost.exe")
| table _time host User img CommandLine ParentImage ParentCommandLine

## E) File created in Downloads (Sysmon EID 11)
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11
| eval tgt=coalesce(TargetFilename,TargetFileName)
| search tgt="*\\Downloads\\*" AND (tgt="*Minecraft.exe" OR tgt="*mimikatz.exe" OR tgt="*svchost.exe")
| table _time host User tgt Image ProcessId

## F) File rename (Sysmon EID 13/14 or 11 depending on config; fallback to Security 4663/4656 where enabled)
### Sysmon (if FileCreateStreamHash / FileCreate / FileDelete / Rename enabled via config)
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| search ("mimikatz.exe" OR "svchost.exe") AND ("Rename" OR "FileRename" OR "File_Renamed" OR EventCode=11 OR EventCode=23 OR EventCode=26)
| table _time host User EventCode Image TargetFilename Message

## G) Object access to credential file (Security 4663)
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4663
| eval obj=coalesce(ObjectName,Object_Name)
| search obj="*\\Credentials.txt" OR like(Message,"%Credentials.txt%")
| table _time host AccountName ProcessName obj AccessMask Accesses Message

## H) Network share access indicators (Security 5140) and UNC references
index=wineventlog sourcetype="WinEventLog:Security" EventCode=5140
| eval share=coalesce(ShareName,Share_Name)
| search share="\\\\10.10.5.86\\*" OR like(Message,"%\\\\10.10.5.86\\%")
| table _time host AccountName share RelativeTargetName IpAddress Message

### Search for lansweeper.ps1 references in any logs
index=* ("lansweeper.ps1" OR "\\\\10.10.5.86\\shared\\lansweeper.ps1")
| table _time host source sourcetype user Message

## I) Covenant / .NET stager hints (process + network)
### Look for suspicious child processes spawned by download payloads
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search (ParentImage="*\\Downloads\\*" OR ParentCommandLine="*\\Downloads\\*") AND (CommandLine="*powershell*" OR CommandLine="*rundll32*" OR CommandLine="*regsvr32*" OR CommandLine="*mshta*")
| table _time host User Image CommandLine ParentImage ParentCommandLine

### Network connections from unusual binaries (Sysmon EID 3)
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| eval img=coalesce(Image,ProcessPath)
| search img="*\\Downloads\\*" OR img="*\\Users\\*"
| table _time host User img DestinationIp DestinationPort Protocol Initiated

# Elastic / Kibana (KQL)

## A) New user created (Security 4720)
event.code: "4720"

### Focus: cpitter
event.code: "4720" and (winlog.event_data.TargetUserName: "cpitter" or winlog.event_data.SamAccountName: "cpitter")

## B) Service installed (System 7045)
event.code: "7045"

### Focus: cleanup-schedule
event.code: "7045" and (winlog.event_data.ServiceName: "cleanup-schedule" or message: "*cleanup-schedule*")

### Suspicious ImagePath in user-writable paths
event.code: "7045" and (winlog.event_data.ImagePath: "*\\Users\\*" or winlog.event_data.ImagePath: "*\\Downloads\\*" or winlog.event_data.ImagePath: "*\\AppData\\*")

## C) Scheduled task created (Security 4698) / updated (4702)
event.code: ("4698" or "4702") and (winlog.event_data.TaskName: "\\spawn" or message: "*\\spawn*")

## D) Sysmon process create (EID 1) — execution from Downloads + svchost masquerade
event.code: "1" and event.provider: "Microsoft-Windows-Sysmon" and
(
  winlog.event_data.Image: "*\\Downloads\\*" and
  (winlog.event_data.Image: "*\\svchost.exe" or winlog.event_data.Image: "*\\Minecraft.exe" or winlog.event_data.Image: "*\\mimikatz.exe")
)

### svchost outside System32/SysWOW64
event.code: "1" and event.provider: "Microsoft-Windows-Sysmon" and
winlog.event_data.Image: "*\\svchost.exe" and
not winlog.event_data.Image: ("C:\\Windows\\System32\\svchost.exe" or "C:\\Windows\\SysWOW64\\svchost.exe")

## E) Security object access (4663) — Credentials.txt
event.code: "4663" and (winlog.event_data.ObjectName: "*\\Credentials.txt" or message: "*Credentials.txt*")

---

## F) SMB share access (5140) — remote host
event.code: "5140" and (winlog.event_data.ShareName: "\\\\10.10.5.86\\*" or message: "*\\\\10.10.5.86\\*")

## G) Sysmon network connection (EID 3) from user-writable paths
event.code: "3" and event.provider: "Microsoft-Windows-Sysmon" and
(winlog.event_data.Image: "*\\Downloads\\*" or winlog.event_data.Image: "*\\Users\\*")

## Query Usage Tips

- Start broad (EIDs 4720/7045/4698/4663/5140), then pivot into Sysmon EID 1/3/11 if available.
- Filter by host `MAGENTA` and constrain time to the incident date window first.
- Add allowlists for known admin tooling and expected service/task deployments once baseline is understood.
