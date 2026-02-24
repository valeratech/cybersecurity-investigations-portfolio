# 006 – Memory Forensics: WMI → PowerShell → LSASS Dump

**Case Title:** WMI-Spawned PowerShell with LSASS Credential Dump  
**Case ID:** 006  
**Date Created:** 2026-02-24  
**Last Updated:** 2026-02-24  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Overview

### Objective
Analyze a Windows memory dump to determine the extent of compromise, identify attacker execution flow, validate credential access activity, extract network indicators, and reconstruct an initial timeline of events.

### Scenario Summary
You work for a managed service provider and were tasked with analyzing a memory dump from a breached customer environment. The goal is to identify hidden processes, suspicious parent/child relationships, evidence of credential dumping, and any active network connections indicative of command-and-control.

This investigation was performed in a CyberDefenders CyberRange “Memory Forensics” scenario using Volatility plugins and supporting utilities.

### Key Focus Areas
- Memory Forensics
- Incident Reconstruction
- Credential Access (LSASS Dumping)
- Network Artifact Identification (C2)
- MITRE ATT&CK TTP Mapping

## 2. Environment & Tools Used

### Environment Description
- Suspected OS: Windows 10 x64
- Confirmed Volatility Profile: `Win10x64_17763`
- Memory Image Timestamp (from Volatility): `2023-02-03 13:29:33 UTC`
- Note: All timestamps are treated as UTC unless explicitly stated otherwise by the CyberRange.

### Tools & Frameworks

**Memory Forensics**
- Volatility Framework 2.6.1 (Python `vol.py`)
  - `imageinfo`
  - `kdbgscan`
  - `pstree`
  - `psxview`
  - `cmdline`
  - `psinfo`
  - `netscan`
  - `mftparser`
  - (scenario-referenced) `pslist`, `filescan`, `dumpfiles`

**Command-Line / Utilities**
- Python (Volatility execution)
- PowerShell (preferred over CMD; filtering via `Select-String`)
- `strings` utility (strings extraction / parsing)

**Forensic GUI / Carving**
- R-Studio (file carving / recovery validation)

**Adversary Tooling**
- Sysinternals ProcDump (inferred from `-accepteula -ma` usage), masqueraded as `lsass.exe`

## 3. Evidence Collected

### Evidence Artifacts
- `memory.dmp` (Windows memory image)
- `strings_out.txt` (pre-generated strings output provided by lab)
- `mftparser.json` (MFT parsing output)
- File artifact referenced/identified:
  - `C:\Windows\System32\svchost.bat`
  - `C:\Windows\lsass.dmp` (LSASS dump output file referenced by command line)

> Note: Evidence binaries (memory dumps, recovered malware/dumps) are not included in this public portfolio repository. Only metadata and investigative notes are stored.

## 4. Analysis & Findings

### 4.1 Profile Identification
The correct profile was identified using:
- `python vol.py -f "C:\...\memory.dmp" imageinfo`

Selected profile:
- `Win10x64_17763`

Kernel debugger scan confirmed profile and key structure:
- `KdCopyDataBlock (V): 0xf8034da8a4d8`

### 4.2 Initial Indicators (Process Tree Pivot)
Suspicious execution chain identified via pstree:
- `WmiPrvSE.exe (PID 1944) → powershell.exe (PID 5104) → conhost.exe (PID 896)`

This is consistent with WMI-driven execution and LOLBAS-style activity.

Likely compromise time marker (PowerShell start time):
- `2023-02-03 13:23:40 UTC`

### 4.3 Credential Access (LSASS Dump)
Cross-view process validation (psxview) revealed two lsass.exe instances:
Legitimate: 
- `lsass.exe (PID 656) → C:\Windows\system32\lsass.exe`
Suspicious/masqueraded:
- `lsass.exe (PID 1576)` with ProcDump-like arguments

Suspicious command line:
- `"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp`

Interpretation:
- A Sysinternals ProcDump-like credential dumping action targeted the legitimate LSASS process (PID 656) and produced `lsass.dmp`.

### 4.4 Command-and-Control (C2) Artifact
A malicious batch file was identified:
- `C:\Windows\System32\svchost.bat`

Defanged C2 endpoint extracted from strings analysis:
- `10[.]0[.]128[.]2:4337`

Active connection observed via netscan (defanged):
- Local: `10[.]0[.]128[.]0:63944`
- Remote: `10[.]0[.]128[.]2:4337`
- State: `ESTABLISHED`

Source port used by the compromised host:
- `63944`

### 4.5 File System Artifact Timestamp (MFT)
MFT parsing (mftparser) indicates file creation:

- `Windows\System32\svchost.bat`
- Creation time: `2023-02-03 13:25:04 UTC`

## 5. Initial Timeline (UTC)
| Time (UTC) | Event |
| :--- | :--- |
| 2023-02-03 13:10:37 | `WmiPrvSE.exe` (PID 1944) created |
| 2023-02-03 13:23:40 | `powershell.exe` (PID 5104) created |
| 2023-02-03 13:25:04 | `svchost.bat` created (`Windows\System32\svchost.bat`) |
| 2023-02-03 13:29:30 | Masqueraded `lsass.exe` (PID 1576) launched to dump LSASS |
| 2023-02-03 13:29:33 | Memory image timestamp (Volatility reported) |

## 6. Indicators (Defanged)
| Type | Indicator |
| :--- | :--- |
| **C2 IP:Port** | `10[.]0[.]128[.]2:4337` |
| **Local Source Port** | `63944` |
| **File Artifact** | `C:\Windows\System32\svchost.bat` |
| **Dump Output** | `C:\Windows\lsass.dmp` |
| **Suspect Process** | `WmiPrvSE.exe (PID 1944)` |
| **Execution Process** | `powershell.exe (PID 5104)` |
| **Masqueraded Dumper** | `lsass.exe (PID 1576)` |

## 7. MITRE ATT&CK (Initial Mapping)
- T1059 — Command and Scripting Interpreter (PowerShell)
- T1047 — Windows Management Instrumentation (WMI execution chain)
- T1003.001 — OS Credential Dumping: LSASS Memory
- T1071 — Application Layer Protocol (C2 via TCP client behavior)

## 8. Notes / Caveats
- This is a memory-focused CyberRange investigation; disk artifacts are referenced where supported by MFT parsing and recovered file properties.
- Evidence files are not included; metadata, analysis steps, and findings are documented for portfolio purposes.
