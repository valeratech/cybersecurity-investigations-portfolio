# Case 003 — Initial Scope & Alert Triage

**Document Type:** Case Note  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose of This Section
This document captures the initial scope of the investigation and the first round of alert triage performed against the provided PCAP. The goal is to identify suspicious activity associated with the HR website and determine whether further investigation is warranted.

## Initial Investigation Scope

### Assets in Scope
- Public-facing HR website: `hr[.]compliantsecure[.]store`
- Backend web server: `HRWEBSERVER` (`10[.]10[.]3[.]115`)
- Network traffic contained within the provided PCAP

### Areas Not Covered by This Triage
- End-user endpoints not communicating with the HR web server
- Email or non-network-based attack vectors
- Infrastructure not visible within the PCAP dataset

## Triggering Indicators

The investigation was initiated after reviewing IDS alerts indicating suspicious and potentially malicious web activity targeting the HR website. Early indicators suggested:

- Web directory and environment enumeration
- Attempts to access sensitive server paths
- Signs of web reconnaissance
- Indicators consistent with web exploitation attempts

## Alert Triage Summary

Initial triage was conducted by aggregating Suricata alerts by `alert.signature`. The following alert signatures were observed and deemed relevant to the investigation:

### Notable Web-Related Alerts
- `GPL WEB_SERVER printenv access`
- `GPL WEB_SERVER /~root access`
- `GPL WEB_SERVER global.asa access`
- `ET WEB_SERVER WEB-PHP phpinfo access`
- `ET WEB_SERVER WebShell Generic - ASP File Uploaded`

Source attribution at this stage: of the signatures above, two are accompanied in the initial triage record by alert records that identify a source — `GPL WEB_SERVER printenv access` and `GPL WEB_SERVER /~root access`. The remaining three appear here as signature counts only.

Analyst interpretation: these signature types are generally associated with:
- Web server reconnaissance
- Attempts to enumerate environment variables and configuration files
- Discovery or exploitation of misconfigured or vulnerable web applications

## Attacker Attribution (Preliminary)

The two source-attributed web alerts in this triage shared a common source IP address:

- **Suspected attacker IP:** `3[.]68[.]76[.]39`
- **Target system:** `10[.]10[.]3[.]115` (HRWEBSERVER)
- **Protocol:** HTTP over TCP/80

The two source-attributed alerts record web probing consistent with directory and environment enumeration against the HR web application from this source.

## Key Alert Evidence (Examples)

### GPL WEB_SERVER printenv access
- **Timestamp:** 2025-05-20 18:15:59Z  
- **Source IP:** 3[.]68[.]76[.]39  
- **Destination IP:** 10[.]10[.]3[.]115  
- **Category:** Access to potentially vulnerable web application  

### GPL WEB_SERVER /~root access
- **Timestamp:** 2025-05-20 18:15:52Z  
- **Source IP:** 3[.]68[.]76[.]39  
- **Destination IP:** 10[.]10[.]3[.]115  
- **Category:** Attempted Information Leak  

## Initial Assessment

Based on the two source-attributed web alerts described above, the activity originating from `3[.]68[.]76[.]39` was assessed as **malicious reconnaissance**.

At this stage, the working hypothesis was:
> The HR web server is being actively targeted, and the attacker may be attempting to discover or exploit a web-based vulnerability.

## Next Investigative Pivot

Following this initial triage, the investigation pivoted to:

- Confirming attacker behavior through packet-level analysis
- Identifying reconnaissance tooling (e.g., port scanning)
- Determining whether exploitation occurred (e.g., file uploads or webshell activity)

**Next file:**  
`analysis/001-alert-triage-signatures-and-filters.md`
