# Indicators of Compromise (IOCs)

**Document Type:** IOC Collection  
**Case ID:** 006-memory-forensics-wmi-powershell-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Malicious Indicators

| Type | Indicator (defanged) | Basis |
|------|----------------------|-------|
| IP:port | 10[.]0[.]128[.]2:4337 | Remote endpoint observed in netscan; malicious role range-confirmed |
| File path | C:\Windows\lsass.exe | Observed image path of the masqueraded process (PID 1576) |
| File path | C:\Windows\System32\svchost.bat | Filename range-confirmed as attacker-created; MFT entry observed |
| File name | lsass.dmp | Output name in the observed command line; no file observed |
| Command line | `"C:\Windows\lsass.exe" -accepteula -ma 656 lsass.dmp` | Observed (cmdline, psinfo) |

## 2. Affected Assets

The imaged Windows 10 x64 host (profile `Win10x64_17763`). No hostname, domain or account
name is recorded in the surviving notes.

## 3. Credential-Targeted Services

| Service | Basis |
|---------|-------|
| LSASS, `lsass.exe` (PID 656, `C:\Windows\system32\lsass.exe`) | Target PID of the observed dump invocation; whether credentials were obtained is not established |

## 4. Contextual Observables — Not IOCs

| Observable | Value | Note |
|------------|-------|------|
| Local endpoint | 10[.]0[.]128[.]0:63944 | Capture-specific session detail; ephemeral source port |
| Connection state | ESTABLISHED, owner PID -1 | State at capture; no owning process recorded |
| Process identifiers | 1944 (`WmiPrvSE.exe`), 5104 (`powershell.exe`), 1576 (`lsass.exe`), 656 (`lsass.exe`) | Capture-specific; meaningful only within this image |

## IOC Summary

- The remote endpoint's malicious role, and `svchost.bat`'s, are range-confirmed.
- The masqueraded image path and its command line are observed.
- Port 63944 and the process identifiers are session details of this image, not durable
  indicators.
