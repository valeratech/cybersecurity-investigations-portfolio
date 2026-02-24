# Process Analysis

**Case ID:** 006  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Identify malicious execution flow, detect masquerading behavior, and confirm credential access activity using cross-view process analysis.

## 2. Profile Context

- Profile: `Win10x64_17763`
- KdCopyDataBlock (V): `0xf8034da8a4d8`
- Memory Timestamp: `2023-02-03 13:29:33 UTC`

## 3. Suspicious Execution Chain

Identified via `pstree`:
```
WmiPrvSE.exe (PID 1944)
└── powershell.exe (PID 5104)
└── conhost.exe (PID 896)
```

### Observations

- WMI spawning PowerShell is consistent with remote execution.
- PowerShell start time: `2023-02-03 13:23:40 UTC`
- Occurs post-login session initialization.
- High-confidence attacker execution pivot: **PID 1944**

## 4. Cross-View Analysis (psxview)

Command used:

`python vol.py -f memory.dmp --profile=Win10x64_17763 psxview`

### Duplicate LSASS Processes Identified
| PID | Path | pslist | Notes |
| :--- | :--- | :---: | :--- |
| 656 | C:\Windows\System32\lsass.exe | True | Legitimate |
| 1576 | C:\Windows\lsass.exe | False | **Suspicious** |

### Indicators of Masquerading
- Incorrect binary path (`C:\Windows\` instead of `System32`)
- Inconsistent visibility across listing mechanisms
- Short-lived process behavior

## 5. Command Line Analysis
Extracted via:

`python vol.py -f memory.dmp --profile=Win10x64_17763 cmdline --offset=0x0000000030581080`

Command:

`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

### Interpretation
Matches Sysinternals ProcDump syntax:

- `accepteula` → Suppresses license prompt
- `-ma` → Full memory dump
- `656` → Target PID (real LSASS)
- `lsass.dmp` → Dump output file

**Conclusion**:

Credential dumping executed against LSASS.

## 6. Parent Process Validation
Validated via `psinfo`:

`python vol.py -f memory.dmp --profile=Win10x64_17763 psinfo -o 0x0000000030581080`

Parent PID:

- `5104` (powershell.exe)

Confirmed chain:
```
WmiPrvSE.exe (1944)
    → powershell.exe (5104)
        → lsass.exe (1576 - masqueraded ProcDump)
```

## 7. Additional Anomaly
Observed unnamed process:
- PID: `393216`
- Timestamp: `1970-01-01 00:00:00 UTC`

Possible explanations:

- Unlinked EPROCESS structure
- DKOM artifact
- Memory parsing artifact

Requires deeper kernel validation in real-world IR.

## 8. MITRE ATT&CK Mapping
| Technique | ID | Evidence |
| :--- | :--- | :--- |
| Windows Management Instrumentation | T1047 | WmiPrvSE spawning PowerShell |
| Command and Scripting Interpreter | T1059 | PowerShell execution |
| Credential Dumping – LSASS | T1003.001 | ProcDump-style LSASS dump |
| Masquerading | T1036 | Renamed lsass.exe binary |

## 9. Assessment
- WMI used for execution
- PowerShell used as staging layer
- Renamed ProcDump executed
- LSASS memory dumped
- Credential access confirmed

## 10. Process-Level Conclusion
  
**Compromise Status:** Confirmed  
**Primary Technique:** LSASS memory dumping (ProcDump-like)  
**Execution Chain:** WmiPrvSE.exe → powershell.exe → masqueraded lsass.exe  

