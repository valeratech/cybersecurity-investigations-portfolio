# Case 003 — Initial Scope & Alert Triage

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose of This Section
This document captures the initial scope of the investigation and the first round of alert triage performed against the provided PCAP. The goal is to identify suspicious activity associated with the HR website and determine whether further investigation is warranted.

## Initial Investigation Scope

### Assets in Scope
- Public-facing HR website: `hr.compliantsecure.store`
- Backend web server: `HRWEBSERVER` (`10.10.3.115`)
- Associated internal infrastructure reachable from the web server
- Network traffic contained within the provided PCAP

### Assets Explicitly Out of Scope (Initial Phase)
- End-user endpoints not communicating with the HR web server
- Email or non-network-based attack vectors
- Infrastructure not visible within the PCAP dataset

## Triggering Indicators

The investigation was initiated after reviewing IDS alerts indicating suspicious and potentially malicious web activity targeting the HR website. Early indicators suggested:

- Web directory and environment enumeration
- Attempts to access sensitive server paths
- Signs of automated reconnaissance
- Indicators consistent with web exploitation attempts

## Alert Triage Summary

Initial triage was conducted by aggregating Suricata alerts by `alert.signature`. The following alert categories were observed and deemed relevant to the investigation:

### Notable Web-Related Alerts
- `GPL WEB_SERVER printenv access`
- `GPL WEB_SERVER /~root access`
- `GPL WEB_SERVER global.asa access`
- `ET WEB_SERVER WEB-PHP phpinfo access`
- `ET WEB_SERVER WebShell Generic - ASP File Uploaded`

These alerts are commonly associated with:
- Web server reconnaissance
- Attempts to enumerate environment variables and configuration files
- Discovery or exploitation of misconfigured or vulnerable web applications

## Attacker Attribution (Preliminary)

Multiple high-confidence alerts shared a common source IP address:

- **Suspected attacker IP:** `3.68.76.39`
- **Target system:** `10.10.3.115` (HRWEBSERVER)
- **Protocol:** HTTP over TCP/80

This IP was repeatedly observed performing actions consistent with directory enumeration and reconnaissance against the HR web application.

## Key Alert Evidence (Examples)

### GPL WEB_SERVER printenv access
- **Timestamp:** 2025-05-20 18:15:59Z  
- **Source IP:** 3.68.76.39  
- **Destination IP:** 10.10.3.115  
- **Category:** Access to potentially vulnerable web application  

### GPL WEB_SERVER /~root access
- **Timestamp:** 2025-05-20 18:15:52Z  
- **Source IP:** 3.68.76.39  
- **Destination IP:** 10.10.3.115  
- **Category:** Attempted Information Leak  

These alerts strongly suggest intentional probing of the web server rather than benign user activity.

## Initial Assessment

Based on alert frequency, consistency, and behavior patterns, the activity originating from `3.68.76.39` was assessed as **malicious reconnaissance** rather than false positives or misconfiguration noise.

At this stage, the working hypothesis was:
> The HR web server is being actively targeted, and the attacker may be attempting to discover or exploit a web-based vulnerability.

## Next Investigative Pivot

Following this initial triage, the investigation pivoted to:

- Confirming attacker behavior through packet-level analysis
- Identifying reconnaissance tooling (e.g., port scanning)
- Determining whether exploitation occurred (e.g., file uploads or webshell activity)

**Next file:**  
`analysis/001-alert-triage-signatures-and-filters.md`
