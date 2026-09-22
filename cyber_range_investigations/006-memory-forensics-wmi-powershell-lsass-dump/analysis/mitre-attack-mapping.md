# MITRE ATT&CK Mapping

**Document Type:** Analysis  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Objective and Version

Map the recorded evidence to ATT&CK techniques, keeping the provenance of the evidence
separate from the disposition of each technique.

- **ATT&CK version:** Enterprise v19.2. Technique identifiers and names are given as
  published in that version. Tactic assignments are not reproduced here; they are
  version-dependent (v19 split the former Defense Evasion tactic).
- **Disposition terms:** *Supported* — the technique's defining behaviour is observed;
  *Invocation observed* — the action was requested but its outcome is not recorded;
  *Consistent with* — the observation fits the technique but does not establish it.

## 2. Mapped Techniques

| Technique | ID | Evidence and provenance | Disposition |
|-----------|----|-------------------------|-------------|
| OS Credential Dumping: LSASS Memory | T1003.001 | Observed: PID 1576 command line `-accepteula -ma 656 lsass.dmp` targets PID 656, the legitimate LSASS. Analyst inference: ProcDump full-dump syntax. | Invocation observed; completion and credential access not established |
| Masquerading | T1036 | Observed: a process named `lsass.exe` running from `C:\Windows\` with non-LSASS arguments. Range-confirmed: a renamed Sysinternals tool. | Supported for the name and path mismatch |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Observed: `powershell.exe` (PID 5104), child of `WmiPrvSE.exe`, recorded parent of PID 1576. Its command line and script content were not recorded; PowerShell code appears only in the range-supplied strings output. | Supported that PowerShell ran and parented PID 1576; its commands are not recorded |
| Windows Management Instrumentation | T1047 | Observed: `WmiPrvSE.exe` (PID 1944) is the parent of PID 5104. The WMI method, consumer or caller is not recorded. | Consistent with; not established |

## 3. Considered and Not Mapped

| Technique | ID | Reason not mapped |
|-----------|----|-------------------|
| Application Layer Protocol | T1071 | No application-layer protocol was observed; the recorded code opens a raw TCP socket |
| Non-Standard Port | T1571 | Port 4337 alone does not establish a protocol-to-port mismatch, and the protocol in use was not observed |
| Ingress Tool Transfer | T1105 | No file or tool transfer was observed |
| Access Token Manipulation | T1134 | No handle or token data was recorded; the `handles` plugin was not run |
| Hide Artifacts | T1564 | Absence from `pslist` was not tested for cause and does not by itself establish hiding |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | No execution of `svchost.bat` was observed |

## 4. Scope Assessment

| Category | Status |
|----------|--------|
| Process execution chain | Observed (WmiPrvSE → PowerShell → masqueraded `lsass.exe`, last link by recorded PPID) |
| LSASS dump | Invocation observed; outcome not established |
| Command and control | Connection observed at capture with no recorded owner; malicious role range-confirmed |
| Persistence | Not examined |
| Lateral movement | Not examined |
| Data exfiltration | Not examined |

## 5. Mapping Conclusion

Four techniques are mapped, each at the strength its evidence supports. No mapping in this
document asserts that credential material was obtained, that a command channel carried
traffic, or that a technique occurred beyond what the recorded artifacts show.
