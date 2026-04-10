# Investigation Report

**Document Type:** Investigation Summary  

**Case Title:** Web Upload Abuse → Cobalt Strike C2 → Lateral Movement & Exfiltration  
**Case ID:** 002-web-upload-cobalt-strike-lateral-exfiltration  
**Date Created:** 2026-01-08  
**Last Updated:** 2026-01-08  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Overview

### Objective
The objective of this investigation is to analyze a suspected compromise originating from a public-facing web application. The investigation focuses on identifying the initial access vector, malicious payload delivery, command-and-control (C2) activity, internal lateral movement, and attempted data exfiltration through detailed network forensic analysis.

### Scenario Summary
This investigation is based on a CyberDefenders CyberRange scenario in which an organization operates a public website with a contact-us form used to receive customer inquiries. An Endpoint Detection and Response (EDR) alert was triggered on the web server, indicating the presence of a malicious file within the upload directory associated with the contact form.

A network packet capture (PCAP) was provided for analysis to determine how the attacker gained access, what payload was delivered, how command-and-control was established, and what activity occurred within the internal network following the compromise.

### Key Focus Areas
- Network Forensics  
- Web Application Abuse  
- Malware Delivery & Execution  
- Command-and-Control (C2) Analysis  
- Lateral Movement & Data Exfiltration  

## 2. Environment & Tools Used

### Environment Description
- Source Platform: CyberDefenders CyberRange  
- Evidence Type: Network packet capture (PCAP)  
- Affected Systems:
  - Public-facing web server
  - Internal Windows endpoints
- Network Context:
  - Private internal address space
  - External attacker-controlled infrastructure  
- Time Standard:
  - All timestamps are treated as UTC unless explicitly stated otherwise  

### Tools & Frameworks
A complete inventory of tools, platforms, protocols, commands, and file artifacts used during this investigation is documented in:

`analysis/tools-and-artifacts-used.md`

## 3. Evidence Collected

### Evidence Artifacts
- Network packet capture (PCAP)  
- IDS/IPS alert telemetry (Suricata)  
- Zeek HTTP, DNS, and connection logs  
- Extracted malicious payload artifacts (ISO, LNK, EXE)  
- Hashes and metadata for extracted files  

Detailed acquisition notes, hashes, and tracking are maintained in:

`evidence-metadata/evidence-inventory.md`

## 4. Analysis & Findings

Analysis is documented incrementally and supported by detailed case notes and analytical artifacts located in the `analysis/` and `case-notes/` directories.

### 4.1 Initial Indicators
Initial alert triage revealed high-volume outbound HTTP traffic flagged by IDS signatures consistent with Cobalt Strike Beacon activity. Alerts predominantly involved repeated connections to an external destination over TCP port 80, along with additional TCP stream anomalies and SMB-related alerts suggesting potential internal lateral movement.

### 4.2 Timeline Reconstruction
A complete timeline is maintained in:

`analysis/timeline-utc.md`

### 4.3 Host-Based Analysis
Host-based forensic analysis is limited in this scenario due to the absence of disk or memory images. Findings are inferred through network telemetry and protocol-level inspection.

### 4.4 Network Analysis
Network analysis focuses on:
- HTTP-based command-and-control beaconing  
- Malicious file upload via web application POST request  
- Internal SMB activity indicative of lateral movement  
- RDP session activity between compromised internal systems  

Supporting queries, filters, and packet-level evidence are documented in the `analysis/` directory.

### 4.5 Memory Analysis
Memory analysis was not conducted due to the absence of volatile memory artifacts in the provided evidence set.

### 4.6 Malware Behavior
Malware behavior analysis includes:
- Delivery via ISO file upload  
- Embedded PowerShell execution  
- Disabling of Windows Defender real-time protection  
- Execution of secondary payloads  
- Establishment of persistent C2 communication  

## 5. Indicators of Compromise

Confirmed and normalized indicators of compromise (IOCs) are documented in:

`iocs/network-iocs.md`

## 6. Conclusion

This section will be populated upon completion of full timeline reconstruction, validation of all findings, and correlation of attacker activity across the environment.

## 7. Appendix (Planned)
- MITRE ATT&CK Mapping  
- Detection & Prevention Opportunities  
- Key Takeaways for Blue Team Operations  
