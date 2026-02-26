# Timeline Reconstruction

**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Time Standard:** UTC  

## Timeline Overview

This timeline consolidates artifacts recovered from:

- Extracted EVTX logs (reconstructed from memory)
- Sysmon Event Logs
- Service Creation Logs (7045)
- Memory string analysis
- Volatility metadata

All timestamps are normalized to UTC.

## 2025-05-26 – Tool Staging & Preparation Phase

### 12:32:38
- Chrome downloads temporary file into Administrator Downloads directory.
- Indicates initial tool acquisition activity.

### 12:32:40
- `DumpIt.exe` observed in Downloads.
- Memory acquisition tooling present on system.

### 12:32:48
- `DumpIt.sys` driver written to:
  ```
  C:\Windows\SysWOW64\drivers\DumpIt.sys
  ```

### 12:42:30
- `winpmem_mini_x64_rc2.exe` observed.
- Additional memory acquisition tooling staged.

### 12:48:06
- `DumpIt.exe` moved into:
  ```
  C:\Users\Administrator\Tools\
  ```

## 2025-05-27 – Active Intrusion Phase

### 09:17:33 – 09:17:52
- Numerous .NET native image DLL creations via `mscorsvw.exe`
- Likely background compilation activity
- No direct malicious indicators but included for completeness

### 09:21:40
- RDP connection accepted from:
  ```
  192.168.19.159
  ```
- Client source port: `64984`
- Destination port: `3389`

### 09:21:58
Tool staging observed under:

```
C:\Users\Public\Downloads\N1\N1\
```

Files created:

- `DD.exe`
- `SB.exe` (renamed Seatbelt)
- `tt.exe`
- `n1.ps1`

### 09:22:22
Tools relocated to execution directory:

```
C:\Users\Default\AppData\Local\Temp\N1\
```

Files observed:

- `DD.exe`
- `SB.exe`
- `tt.exe`
- `n1.ps1`

### 09:22:XX
Service Created:

- Service Name: `FireFox Update`
- Start Type: `Auto Start`
- Account: `LocalSystem`
- ImagePath:
  ```
  C:\Windows\System32\cmd.exe /c "powershell -WindowStyle Hidden -EncodedCommand <base64>"
  ```

Decoded command launches:

```
C:\ProgramData\chocolatey\tt.exe
```

Persistence established.

### 09:23:45
PowerShell script execution observed:
```
__PSScriptPolicyTest_*.ps1
```

Indicates script execution environment active.

### 09:XX (Post Service Execution)
Credential dumping command identified in memory:

```
C:\Users\Default\AppData\Local\Temp\N1\DD.exe -accepteula -ma lsass.exe C:\Users\Default\AppData\Local\Temp\mm.tmp
```

LSASS memory dump written to:
```
C:\Users\Default\AppData\Local\Temp\mm.tmp
```

### Lateral Movement Activity

Recovered command:

```
wmic /node:192.168.19.163 /user:noah /password:"<REDACTED>"
```

Associated Target:
- `192.168.19.163`
- Remote host: `DESKTOP-U98A16J`

Associated SID:
```
S-1-5-21-2346552008-2584940806-3566241850-500
```

## Attack Chain Summary

1. Tool staging via RDP-accessed session
2. Renamed discovery tooling (`Seatbelt` → `SB.exe`)
3. Service persistence created (FireFox Update)
4. Encoded PowerShell execution
5. Credential dumping via `DD.exe`
6. Lateral movement using `WMIC`

## Timeline Confidence Assessment

High confidence:
- RDP ingress timing
- Service creation
- Tool staging
- LSASS dump command
- WMIC lateral movement

Moderate confidence:
- Exact second of credential dump execution (derived from strings, not direct process creation event)

## Upper Bound Constraint

Memory capture time:
```
2025-05-27 09:30:20 UTC
```

All attacker activity occurred prior to this timestamp.
