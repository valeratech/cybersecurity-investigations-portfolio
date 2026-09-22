# Incident Flow Diagram

**Document Type:** Analysis  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Recorded Process Lineage (observed)

```
svchost.exe (PID 884)
│
▼
WmiPrvSE.exe (PID 1944)
│
▼
powershell.exe (PID 5104)
│
│ recorded PPID of PID 1576 (psinfo)
▼
lsass.exe (PID 1576, C:\Windows\lsass.exe)
│
│ command line: -accepteula -ma 656 lsass.dmp
▼
dump invoked against lsass.exe (PID 656); outcome not recorded
```

## Separately Recorded Artifacts (no observed link to the lineage)

```
netscan:    10[.]0[.]128[.]0:63944 -> 10[.]0[.]128[.]2:4337  ESTABLISHED  owner PID -1

mftparser:  Windows\System32\svchost.bat  $STANDARD_INFORMATION 2023-02-03 13:25:04 UTC+0000
```

## Flow Summary

Observed: WmiPrvSE → PowerShell → masqueraded `lsass.exe` with a dump invocation against
LSASS. Range-confirmed: `svchost.bat` was attacker-created and used the connection to
`10[.]0[.]128[.]2:4337`. The surviving record does not link the connection or the batch
file to the process lineage.
