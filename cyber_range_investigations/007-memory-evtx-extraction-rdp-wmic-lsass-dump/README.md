# Investigation Report

**Case Title:** Memory EVTX Extraction + RDP Intrusion + WMIC Lateral Movement + LSASS Dump  
**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Date Created:** 2026-02-26  
**Last Updated:** 2026-02-26  
**Author:** Ryan Valera  
**Time Standard:** UTC (All timestamps treated as UTC unless explicitly stated by CyberDefenders)  
**Source Platform:** CyberDefenders CyberRange – Memory Forensics Module  

## Scope

This investigation focuses exclusively on analysis of the provided Windows memory image (`Server.raw`).  
No disk image or external log sources were provided.

## Assumptions

- The memory image was acquired in a forensically sound manner.
- System clock was accurate at the time of acquisition.
- All timestamps are normalized to UTC.

## 1. Overview

### Objective

- Identify initial access vector
- Extract Windows Event Logs (EVTX) from memory
- Reconstruct `.vacb` log fragments
- Identify attacker tooling and renamed binaries
- Confirm credential dumping activity
- Identify persistence mechanisms
- Trace lateral movement activity
- Associate malicious actions with user SID

### Scenario Summary

A Windows memory image was provided from a suspected compromised system within a CyberDefenders CyberRange environment.  

Primary investigative focus was extraction of EVTX artifacts from memory using Volatility and reconstruction of attacker activity through timeline correlation.

### Key Focus Areas

- Memory Forensics  
- Event Log Reconstruction  
- RDP Activity Analysis  
- Credential Dumping  
- Persistence Mechanisms  
- Lateral Movement  
- Incident Reconstruction  

## 2. Environment & Tools Used

### Environment Description

- OS Profile: `Win10x64_17763`
- Hostname: `WIN-2O66FDBAHOG`
- Memory Image: `Server.raw`
- Image Capture Time (UTC): `2025-05-27 09:30:20`

### Tools & Frameworks

**Memory Analysis**
- Volatility Framework 2.6.1  
  - `imageinfo`
  - `kdbgscan`
  - `dumpfiles`

**Event Log Processing**
- EvtxECmd (Eric Zimmerman)
- Timeline Explorer

**Artifact Processing**
- PowerShell
- `strings64.exe`

**Identified LOLBins**
- `WMIC.exe`
- `cmd.exe`
- `powershell.exe`

## 3. Evidence Collected

### Evidence Artifacts

- Memory image: `Server.raw`
- Extracted EVTX artifacts (from memory)
- Reconstructed EVTX files (from `.vacb`)
- Parsed CSV logs
- Extracted memory strings file

## 4. Analysis & Findings

### 4.1 Initial Indicators

- RDP connection from: `192[.]168[.]19[.]159`
- Suspicious service created: `FireFox Update`
- Suspicious tool staging directory:
  - `C:\Users\Public\Downloads\N1\N1\`
  - `C:\Users\Default\AppData\Local\Temp\N1\`

### 4.2 Timeline Reconstruction (UTC)

**2025-05-26**
- Discovery tooling downloaded
- Seatbelt renamed to `SB.exe`

**2025-05-27**
- RDP connection established
- Service `FireFox Update` created
- Encoded PowerShell execution observed
- LSASS dump executed:
  ```
  C:\Users\Default\AppData\Local\Temp\N1\DD.exe -accepteula -ma lsass.exe C:\Users\Default\AppData\Local\Temp\mm.tmp
  ```
- WMIC lateral movement command:
  ```
  wmic /node:192[.]168[.]19[.]163 /user:noah /password:"<REDACTED>"
  ```

### 4.3 Host-Based Analysis

- Renamed discovery tool:
  - `SB.exe` → Seatbelt.exe
- Credential dumping tool:
  - `DD.exe`
- Persistence:
  - Service Name: `FireFox Update`
  - Executes hidden PowerShell encoded command
  - Launches: `C:\ProgramData\chocolatey\tt.exe`

Associated SID:
- `S-1-5-21-2346552008-2584940806-3566241850-500`

### 4.4 Network Analysis

- RDP ingress: `192[.]168[.]19[.]159`
- Lateral movement target: `192[.]168[.]19[.]163`
- WMIC used for remote enumeration and command execution

### 4.5 Memory Analysis

- EVTX artifacts successfully carved from memory
- `.vacb` fragments reconstructed
- Encoded PowerShell command recovered
- LSASS dumping command recovered via strings analysis

### 4.6 Malware Behavior

Observed behaviors:

- Tool download and staging
- Binary renaming for evasion
- Service-based persistence
- Obfuscated PowerShell execution
- Credential dumping
- Lateral movement via LOLBin

## 5. Indicators of Compromise (Defanged)

### IP Addresses
- `192[.]168[.]19[.]159`
- `192[.]168[.]19[.]163`

### Service Name
- `FireFox Update`

### Suspicious Files
- `C:\Users\Public\Downloads\N1\N1\DD.exe`
- `C:\Users\Public\Downloads\N1\N1\SB.exe`
- `C:\Users\Public\Downloads\N1\N1\tt.exe`
- `C:\Users\Default\AppData\Local\Temp\mm.tmp`

## 6. MITRE ATT&CK Mapping (Preliminary)

- T1021.001 – Remote Services: RDP
- T1059.001 – PowerShell
- T1003.001 – LSASS Memory Dump
- T1047 – Windows Management Instrumentation
- T1543.003 – Windows Service Persistence

## 7. Limitations

- Only memory image provided (no disk image).
- Possible incomplete EVTX reconstruction due to `.vacb` fragment limitations.

## 8. Conclusion (Interim)

Evidence confirms:

- RDP-based access from an internal host
- Tool staging and renaming activity
- Service-based persistence
- Credential dumping targeting LSASS
- Lateral movement using WMIC
- Malicious activity tied to SID `S-1-5-21-2346552008-2584940806-3566241850-500`

Investigation ongoing.

## 9. Next Steps

- Build full second-by-second timeline
- Correlate logon events with process execution
- Identify additional impacted systems
- Validate scope of credential compromise
