# Detection Engineering Notes

**Document Type:** Analysis  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Derive detection ideas from the patterns recorded in this case. These are recommendations.
The exercise supplied a memory image only; the environment's logging, alerting and
protection settings were not examined and are not described here.

Patterns recorded in the image:

- `WmiPrvSE.exe` as the parent of `powershell.exe`
- a process named `lsass.exe` running from `C:\Windows\` with ProcDump-style arguments
  targeting the legitimate LSASS PID
- an ESTABLISHED TCP connection to port 4337, with no owning process recorded

## 2. Detection Opportunities

### 2.1 WmiPrvSE Spawning PowerShell

**Recorded pattern:** `WmiPrvSE.exe` (PID 1944) → `powershell.exe` (PID 5104)

**Detection logic:**

- ParentImage = `WmiPrvSE.exe`
- Image = `powershell.exe`
- Prioritise command lines with encoded or download content

**Sigma concept:**
```
title: WMI Spawning PowerShell
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\WmiPrvSE.exe'
    Image|endswith: '\powershell.exe'
  condition: selection
level: high
```

### 2.2 lsass.exe Outside System32 with Dump Arguments

**Recorded pattern:** `"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

**Detection logic:**

- Image name `lsass.exe` with a path other than `C:\Windows\System32\lsass.exe`
- Command line containing `-ma` or `-accepteula` together with an LSASS PID or name
- Creation of files named `*.dmp` matching `lsass*`

### 2.3 LSASS Process-Access Monitoring (recommended)

This case recorded no handle or process-access data. Recommended coverage:

- Sysmon Event ID 10 (ProcessAccess) with TargetImage `lsass.exe`
- Alert on broad access masks such as `0x1fffff` from unexpected source images

### 2.4 Connections to Uncommon Ports

**Recorded pattern:** ESTABLISHED TCP to `10[.]0[.]128[.]2:4337`; owner PID not recorded.

**Detection logic:**

- Internal or outbound TCP sessions to uncommon high ports
- Correlate network sessions with process-creation events to recover the owning process,
  which memory analysis did not provide here

**Hunting concept (Splunk-style):**

```
index=endpoint Image="*powershell.exe"
| join ProcessId
    [ search index=network dest_port=4337 ]
```

## 3. Behavioral Correlation Strategy

Correlate, where the telemetry exists:

1. WMI provider host process creation
2. PowerShell creation under WmiPrvSE
3. Network sessions opened by the same process tree
4. Access to the LSASS process
5. Dump-file creation

Single events may be noisy; the combination is the stronger signal.

## 4. Preventive Controls (recommended)

| Control | Purpose |
| :--- | :--- |
| **Credential Guard / LSA protection** | Reduce exposure of LSASS memory |
| **Attack Surface Reduction rules** | Block credential stealing from LSASS |
| **Constrained Language Mode** | Restrict PowerShell capabilities |
| **EDR LSASS monitoring** | Detect memory-dump attempts |
| **WMI activity monitoring** | Detect WMI-initiated process creation |

## 5. Recommended Logging

- Sysmon: ProcessCreate, ProcessAccess, NetworkConnect
- PowerShell Script Block Logging
- Security 4688 (process creation, with command line)
- Security 4624 and 4672 (logon and special-privilege assignment)
- WMI-Activity operational log

## 6. Detection Engineering Conclusion

The patterns recorded in this case are detectable with process-creation, process-access
and network telemetry. Whether the environment collected or alerted on such telemetry is
not recorded, so no statement is made about what it did or did not detect.
