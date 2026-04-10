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

- `http[:]//www[.]mindtech[.]net/contact[.]php`
- `/en_US/all.js`

## Files Associated with Malicious Activity

- `Urgent Support.iso`
- `DOCUMENT.LNK`
- `ADOBE.exe`

## Observed Commands

```text
Set-MpPreference -DisableRealtimeMonitoring 1; D:\ADOBE.exe
