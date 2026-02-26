# Final Investigation Report

**Case ID:** 006  
**Case Title:** Memory Forensics – WMI → PowerShell → LSASS Dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

Analysis of the provided Windows 10 memory image confirmed that the system was compromised.

The attacker leveraged WMI to execute PowerShell, established a reverse TCP command channel, and performed credential dumping against LSASS using a renamed Sysinternals ProcDump binary. The malicious session was active at the time of memory acquisition.

## 2. Scope of Analysis

- Windows memory dump (`memory.dmp`)
- Process enumeration and cross-view validation
- Network connection analysis
- File artifact recovery
- Timeline reconstruction
- MITRE ATT&CK mapping

## 3. Key Findings

### 3.1 Initial Execution

- `WmiPrvSE.exe` (PID 1944) spawned `powershell.exe` (PID 5104)
- Execution timestamp: `2023-02-03 13:23:40`

This marks the beginning of attacker-controlled activity.

### 3.2 Command and Control

- Reverse TCP connection established to: `10[.]0[.]128[.]2:4337`
- Local source port: `63944`
- Connection state at capture: `ESTABLISHED`

The compromised host maintained active outbound communication.

### 3.3 Credential Dumping

- Duplicate `lsass.exe` process detected
- Suspicious process (PID 1576) executed:

`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`


- Target: Legitimate LSASS (PID 656)
- Output file: `lsass.dmp`

This confirms credential access via LSASS memory dumping.

## 4. Attack Timeline (UTC)

| Time | Event |
|------|-------|
| 13:23:40 | PowerShell execution via WMI |
| 13:25:04 | svchost.bat created |
| ~13:25 | Reverse TCP session established |
| 13:29:30 | LSASS dump executed |
| 13:29:33 | Memory captured |

## 5. MITRE ATT&CK Techniques

- T1047 – Windows Management Instrumentation  
- T1059.001 – PowerShell  
- T1071 – Application Layer Protocol  
- T1003.001 – LSASS Credential Dumping  
- T1036 – Masquerading  

## 6. Impact Assessment

- **Execution:** Confirmed  
- **Command and Control:** Confirmed  
- **Credential Dumping:** Confirmed  
- **Persistence:** Not observed in memory  
- **Data Exfiltration:** Not observed in memory  

The attacker achieved credential access and maintained interactive control of the system.

## 7. Conclusion

The compromise began at approximately `2023-02-03 13:23:40 UTC`.

The attacker:

1. Executed code via WMI  
2. Spawned PowerShell  
3. Established a reverse TCP shell  
4. Dumped LSASS memory  
5. Maintained active C2 communication  

The system must be considered fully compromised.

Immediate credential rotation and host remediation would be required in a real-world environment.
