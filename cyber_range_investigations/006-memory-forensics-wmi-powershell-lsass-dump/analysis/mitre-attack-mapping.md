# MITRE ATT&CK Mapping

**Case ID:** 006  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Map observed attacker behavior to MITRE ATT&CK techniques based on validated forensic evidence from memory analysis.

## 2. Execution

| Technique | ID | Evidence |
|------------|----|----------|
| Windows Management Instrumentation | T1047 | WmiPrvSE.exe spawning PowerShell |
| Command and Scripting Interpreter: PowerShell | T1059.001 | powershell.exe (PID 5104) execution |

Observed chain:

`WmiPrvSE.exe → powershell.exe → masqueraded lsass.exe`

## 3. Command and Control

| Technique | ID | Evidence |
|------------|----|----------|
| Application Layer Protocol | T1071 | TCP-based reverse shell |
| Ingress Tool Transfer | T1105 | Remote command execution over TCP |
| Non-Standard Port | T1571 | C2 over port 4337 |

Defanged C2 indicator:

`10[.]0[.]128[.]2:4337`


Connection state at capture: `ESTABLISHED`

## 4. Credential Access

| Technique | ID | Evidence |
|------------|----|----------|
| OS Credential Dumping: LSASS Memory | T1003.001 | ProcDump-style memory dump |
| Access Token Manipulation (Potential) | T1134 | Full handle access from PowerShell |

Command executed:

`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

## 5. Defense Evasion

| Technique | ID | Evidence |
|------------|----|----------|
| Masquerading | T1036 | Renamed ProcDump as lsass.exe |
| Hide Artifacts | T1564 | Inconsistent process visibility in psxview |

Suspicious process:

- `PID 1576` not visible in pslist
- Path differs from legitimate LSASS

## 6. Impact Assessment

| Category | Status |
|----------|--------|
| Execution | Confirmed |
| C2 Communication | Confirmed |
| Credential Dumping | Confirmed |
| Persistence | Not Observed |
| Data Exfiltration | Not Observed in Memory |

## 7. Attack Flow Summary

1. WMI used for remote execution  
2. PowerShell spawned under WMI  
3. Reverse shell established over TCP  
4. Renamed ProcDump executed  
5. LSASS memory dumped  
6. C2 active at time of capture  

## 8. Overall ATT&CK Conclusion

The attacker demonstrated:

- Interactive command execution
- Active C2 channel
- Credential access via LSASS dumping
- Defense evasion via masquerading

This activity aligns with post-compromise lateral movement and credential harvesting behavior.
