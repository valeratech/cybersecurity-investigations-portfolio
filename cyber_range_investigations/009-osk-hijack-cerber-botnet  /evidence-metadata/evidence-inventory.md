# Evidence Inventory

**Document Type:** Evidence Metadata

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Evidence Summary

This document tracks all evidence sources used during the investigation. All artifacts remain unmodified and were analyzed in accordance with standard DFIR evidence handling procedures.

## Evidence Table

| Evidence ID | Description | Source | Type | Collection Method | Hash | Notes |
|-------------|------------|--------|------|-------------------|------|-------|
| EVT-001 | Sysmon / Windows Event Logs | Splunk (botsv1 index) | Log Data | SIEM Query (SPL) | N/A | Used for process execution, network connections, and hash extraction |
| EVT-002 | Fortigate UTM Logs | Splunk (botsv1 index) | Network Security Logs | SIEM Query (SPL) | N/A | Provided malware classification and botnet categorization |
| EVT-003 | Suricata IDS Logs | Splunk (botsv1 index) | IDS Alerts | SIEM Query (SPL) | N/A | Identified reconnaissance behavior via alert signatures |
| EVT-004 | Suspicious Binary (`osk.exe`) | Endpoint (logical reference via logs) | Executable (Referenced) | Sysmon Event ID 7 (ImageLoaded) | `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B` | Masquerading binary associated with Cerber malware |
| EVT-005 | Threat Intelligence Report | VirusTotal | External Intelligence | Hash lookup | N/A | Confirmed Cerber ransomware attribution |

## Handling Notes

- All evidence analyzed was derived from SIEM datasets and external intelligence sources.  
- No direct acquisition or modification of original binaries was performed.  
- All analysis was conducted using read-only queries and external enrichment sources.  
- Evidence integrity was maintained throughout the investigation lifecycle.  
