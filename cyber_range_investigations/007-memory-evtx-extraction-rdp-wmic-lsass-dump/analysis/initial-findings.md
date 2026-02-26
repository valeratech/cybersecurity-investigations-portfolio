# Initial Findings

**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Time Standard:** UTC  

## Executive Summary of Confirmed Findings

Analysis of the provided Windows memory image (`Server.raw`) confirms:

- RDP-based access from an internal host
- Tool staging and renaming activity
- Service-based persistence using obfuscated PowerShell
- Credential dumping targeting LSASS
- Lateral movement using WMIC
- Malicious activity tied to a specific SID

All timestamps referenced below are normalized to UTC.

## Finding 1 – Memory Image Acquisition Time

### Observation
Volatility `imageinfo` identified the memory image capture time as:

```
Image date and time : `2025-05-27 09:30:20 UTC+0000`
```

### Conclusion
The memory image was acquired at:

`2025-05-27 09:30:20 UTC`

This timestamp serves as the upper bound for all attacker activity contained in memory.

## Finding 2 – RDP Ingress Source

### Observation
Event log artifacts extracted from memory indicate the host accepted an RDP connection from:

`192.168.19.159`

(Defanged: `192[.]168[.]19[.]159`)

### Conclusion
An internal host at `192[.]168[.]19[.]159` initiated an RDP session to the compromised machine.

## Finding 3 – RDP Connection Ports

### Observation
Event records indicate:

- Client source port: `64984` (ephemeral)
- Destination port: `3389` (RDP service)

### Conclusion
The compromised host accepted an RDP connection on TCP 3389 from client port 64984.

## Finding 4 – Renamed Discovery Tool

### Observation
Sysmon Event ID 11 entries indicate creation of:

`SB.exe`

Staged alongside additional tooling within:

`C:\Users\Public\Downloads\N1\N1\`

Based on known tradecraft and context, `SB.exe` corresponds to:

**Seatbelt.exe**

### Conclusion
The attacker renamed Seatbelt.exe to `SB.exe` to reduce detection likelihood.

## Finding 5 – Malicious Service Persistence

### Observation
Service creation logs indicate the following:

- Service Name: `FireFox Update`
- ImagePath:
  ```
  C:\Windows\System32\cmd.exe /c "powershell -WindowStyle Hidden -EncodedCommand <base64>"
  ```

Decoded PowerShell command launches:

`C:\ProgramData\chocolatey\tt.exe`

### Conclusion
The attacker established persistence via a Windows service named `FireFox Update`, executing obfuscated PowerShell to launch `tt.exe`.

## Finding 6 – Credential Dumping Activity

### Observation
Memory string extraction revealed execution of:

```
C:\Users\Default\AppData\Local\Temp\N1\DD.exe -accepteula -ma lsass.exe C:\Users\Default\AppData\Local\Temp\mm.tmp
```

Switch analysis:

- `-accepteula`
- `-ma lsass.exe` (full memory dump of LSASS)
- Output file: `mm.tmp`

### Conclusion
The attacker used `DD.exe` to dump LSASS memory, indicating credential harvesting activity.

## Finding 7 – Lateral Movement via WMIC

### Observation
Recovered command:

```
wmic /node:192.168.19.163 /user:noah /password:"<REDACTED>"
```

(Defanged IP: `192[.]168[.]19[.]163`)

### Conclusion
The attacker used WMIC (a Windows LOLBin) to perform remote process enumeration or execution against another internal host.

## Finding 8 – SID Attribution

### Observation
Event log correlation identifies the SID associated with malicious activity:

`S-1-5-21-2346552008-2584940806-3566241850-500`

This SID corresponds to the Administrator context observed in event logs.

### Conclusion
Malicious actions were executed under security context:

`S-1-5-21-2346552008-2584940806-3566241850-500`

## Current Assessment

Confirmed attack sequence:

1. RDP ingress from internal host
2. Tool staging and renaming
3. Service-based persistence established
4. Obfuscated PowerShell execution
5. LSASS credential dumping
6. Lateral movement via WMIC

Investigation continues with structured timeline expansion and deeper event correlation.
