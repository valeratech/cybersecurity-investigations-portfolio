# Network Indicators of Compromise

**Document Type:** IOC Collection  
**Case ID:** 002-web-upload-cobalt-strike-lateral-exfiltration  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Scope

This document contains confirmed, normalized, deduplicated, and defanged network-related indicators of compromise identified during the investigation.

Only validated indicators are included.

## External IP Addresses

- `113[.]26[.]232[.]2`

## Internal IP Addresses

- `10[.]0[.]128[.]130`

## Domains

- `www[.]mindtech[.]net`

## URLs / URI Paths

- `hxxp://www[.]mindtech[.]net/contact[.]php`
- `/en_US/all.js`

## Files Associated with Malicious Activity

- `Urgent Support.iso`
- `DOCUMENT.LNK`
- `ADOBE.exe`

## File Hashes

- `Urgent Support.iso` — SHA-256 `935492b3714f140ff4567c14fe0fc13cba6f5df13a2be8a8b14912f2da24d475`

## Rule-Based Detections

- `CobaltStrike_Resources_Artifact64_v3_14_to_v4_x` (THOR APT Scanner, community
  YARA rule via VirusTotal) — identifies the payload as a Cobalt Strike artifact

## Observed Commands

```text
Set-MpPreference -DisableRealtimeMonitoring 1; D:\ADOBE.exe
```
