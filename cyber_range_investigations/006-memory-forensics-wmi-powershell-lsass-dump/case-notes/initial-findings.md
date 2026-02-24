# Initial Findings – 006 Memory Forensics Investigation

**Case ID:** 006  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Initial Objective

Analyze the provided Windows memory image to:

- Identify malicious execution flow  
- Detect hidden or masqueraded processes  
- Determine whether credential dumping occurred  
- Extract any command-and-control indicators  
- Build a preliminary timeline  

## 2. Profile Validation

Volatility `imageinfo` identified multiple suggested profiles.

Selected:

- `Win10x64_17763`

Confirmed via:

- `kdbgscan`
- KdCopyDataBlock (Virtual): `0xf8034da8a4d8`

This confirms Windows 10 x64 Build 17763.

## 3. Process Tree Pivot (Primary Suspicion)

Using `pstree`, identified suspicious execution chain:
```
WmiPrvSE.exe (PID 1944)
└── powershell.exe (PID 5104)
└── conhost.exe (PID 896)
```

### Observations

- WMI spawning PowerShell is a common LOLBAS execution technique.
- PowerShell start time: `2023-02-03 13:23:40 UTC`
- Occurs after system fully initialized → suggests interactive attacker activity.
- Treat PID 1944 as high-priority pivot process.

## 4. Cross-View Process Validation (psxview)

Identified duplicate `lsass.exe` processes:

| PID | Path | Notes |
|------|------|------|
| 656 | `C:\Windows\system32\lsass.exe` | Legitimate |
| 1576 | `C:\Windows\lsass.exe` | Suspicious |

### Suspicious Process (PID 1576)

- Inconsistent visibility in `psxview`
- `pslist = False`
- Indicates possible:
  - Short-lived execution
  - DKOM hiding
  - Recently terminated credential dumping

Command line:

`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

### Interpretation

This matches Sysinternals ProcDump syntax:

- `-ma` → full memory dump
- Target PID: 656 (real LSASS)
- Output: `lsass.dmp`

**Conclusion**: Credential dumping occurred.

## 5. File Artifact Discovery

Identified malicious batch file:

`C:\Windows\System32\svchost.bat`

- Extracted via strings analysis.
- Embedded PowerShell TCP client behavior found.

## 6. Command-and-Control Indicator (Defanged)

Extracted from strings:

`10[.]0[.]128[.]2:4337`

Confirmed via `netscan`:
- Local: `10[.]0[.]128[.]0:63944`
- Remote: `10[.]0[.]128[.]2:4337`
- State: `ESTABLISHED`


Source port used by compromised system:

- `63944`

Indicates active reverse-style TCP command channel.

## 7. Timeline Reconstruction (Preliminary)

| Time (UTC) | Event |
|------------|--------|
| 13:10:37 | WmiPrvSE.exe (PID 1944) created |
| 13:23:40 | PowerShell spawned |
| 13:25:04 | svchost.bat created |
| 13:29:30 | Masqueraded lsass.exe (PID 1576) executed |
| 13:29:33 | Memory capture timestamp |

## 8. Hypothesis

Based on evidence:

1. Attacker achieved WMI-based execution.
2. WMI spawned PowerShell.
3. PowerShell likely created `svchost.bat`.
4. Batch file established TCP C2 to `10[.]0[.]128[.]2:4337`.
5. Attacker executed renamed ProcDump to dump LSASS.
6. Credential theft occurred prior to memory capture.

## 9. Next Investigation Steps

- Validate presence of `lsass.dmp` via `filescan` / `dumpfiles`
- Examine PowerShell command-line history (if recoverable)
- Extract suspicious process memory (PID 1576) for static analysis
- Map activity to MITRE ATT&CK formally
- Develop detection engineering recommendations

## 10. Analyst Notes

- Duplicate WmiPrvSE instances observed (3816 and 1944).
- One unnamed/epoch-timestamp process observed (PID 393216) — may indicate:
  - Corruption
  - Unlinked EPROCESS
  - Parsing artifact

Requires cross-validation with additional plugins.

**Status:** Confirmed compromise with credential dumping and C2 activity.
