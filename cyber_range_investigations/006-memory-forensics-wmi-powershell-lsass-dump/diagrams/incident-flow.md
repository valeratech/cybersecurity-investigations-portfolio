# Incident Flow Diagram

**Case ID:** 006  
**Time Standard:** UTC  

## Attack Sequence
```
Attacker
│
│ (WMI Execution)
▼
WmiPrvSE.exe (PID 1944)
│
▼
powershell.exe (PID 5104)
│
│ Creates
▼
C:\Windows\System32\svchost.bat
│
│ Establishes TCP Session
▼
10[.]0[.]128[.]2:4337 (C2 Server)
│
│ Executes
▼
"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp
│
▼
LSASS Memory Dump (PID 656)
```
## Flow Summary

Execution → C2 Established → Credential Dump → Active Session at Capture

The attacker achieved interactive control and harvested credentials prior to memory acquisition.
