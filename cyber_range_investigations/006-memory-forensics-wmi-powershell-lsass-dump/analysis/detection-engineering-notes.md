# Detection Engineering Notes

**Case ID:** 006  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective

Develop defensive detection strategies based on observed attacker behavior:

- WMI → PowerShell execution
- Reverse TCP shell over non-standard port
- LSASS credential dumping via renamed ProcDump
- Process masquerading

## 2. High-Fidelity Detection Opportunities

### 2.1 WMI Spawning PowerShell

**Behavior Observed:**

`WmiPrvSE.exe → powershell.exe`

**Detection Logic:**

- ParentImage = `WmiPrvSE.exe`
- ChildImage = `powershell.exe`
- CommandLine contains suspicious switches or encoded content

**Sigma Concept:**
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

### 2.2 LSASS Dump via ProcDump Masquerading
Behavior Observed:

`"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

Detection Logic:

- Image path not equal to `System32\lsass.exe`
- CommandLine contains `-ma`
- Target process = `lsass.exe`
- Creation of `lsass.dmp`

High-Signal Indicators:

- Process accessing LSASS with full handle rights
- Duplicate `lsass.exe` processes
- `lsass.exe` executing from non-System32 path

### 2.3 LSASS Handle Access Monitoring

**Detection Criteria**:

- `Event ID 10` (Sysmon ProcessAccess)
- TargetImage = `lsass.exe`
- `GrantedAccess` includes `0x1fffff` or full memory access

### 2.4 Reverse Shell Over Non-Standard Port

**Behavior Observed**:

Outbound connection to:

`10[.]0[.]128[.]2:4337`

Detection Logic:

- Outbound TCP to non-standard high port
- powershell.exe initiating external connection
- ESTABLISHED session from ephemeral source port

SIEM Query Concept (Splunk-style):

```
index=endpoint
(Image="*powershell.exe")
| join ProcessId
    [ search index=network dest_port=4337 ]
```

## 3. Behavioral Correlation Strategy

**Correlate**:
1. WMI execution event
2. PowerShell process creation
3. Outbound TCP connection
4. LSASS memory access
5. Dump file creation

Single events may be noisy.
Combined chain = high-confidence compromise.

## 4. Preventive Controls
| Control | Purpose |
| :--- | :--- |
| **Credential Guard** | Protect LSASS memory |
| **Attack Surface Reduction Rules** | Block credential dumping |
| **Constrained Language Mode** | Restrict PowerShell abuse |
| **EDR LSASS Monitoring** | Detect memory dumping |
| **WMI Execution Monitoring** | Detect remote execution |

## 5. Recommended Logging
**Enable**:
- Sysmon (ProcessCreate, ProcessAccess, NetworkConnect)
- PowerShell Script Block Logging
- Security 4688 (Process Creation)
- Security 4624/4672 (Privilege Escalation)
- WMI Activity Logging

## 6. Detection Engineering Conclusion
- This compromise could have been detected early via:
- WMI spawning PowerShell
- PowerShell initiating outbound TCP connection
- Non-System32 lsass.exe execution
- LSASS full-memory access

### Severity Assessment

- Credential dumping combined with active C2 communication represents a high-severity compromise requiring immediate response.
- Correlated behavioral telemetry across process and network logs would have enabled reliable detection.
