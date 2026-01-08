# Investigation Report

**Case Title:** Web Upload Abuse → Cobalt Strike C2 → Lateral Movement & Exfiltration  
**Case ID:** 002  
**Date Created:** 2026-01-08  
**Last Updated:** 2026-01-08  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

---

## 1. Overview

### Objective
The objective of this investigation is to analyze a suspected security incident involving a malicious file upload to a public-facing web application. The investigation focuses on identifying the initial access vector, malicious payload delivery, command-and-control activity, lateral movement, and attempted data exfiltration through network forensic analysis.

### Scenario Summary
This investigation is based on a CyberDefenders CyberRange scenario in which an organization’s public website includes a contact-us form used to receive customer inquiries. An Endpoint Detection and Response (EDR) alert was triggered on the web server, indicating the presence of a malicious file within the upload directory associated with the contact form.

A network packet capture (PCAP) was provided for analysis to determine how the attacker gained access, what payload was delivered, how command-and-control was established, and what internal activity occurred following compromise.

### Key Focus Areas
- Network Forensics  
- Web Application Abuse  
- Malware Delivery & Execution  
- Command-and-Control (C2) Analysis  
- Lateral Movement & Data Exfiltration  

---

## 2. Environment & Tools Used

### Environment Description
- Source: CyberDefenders CyberRange  
- Evidence Type: Network packet capture (PCAP)  
- Affected Systems:
  - Public-facing web server
  - Internal Windows endpoints
- Network Context:
  - Internal private address space
  - External attacker-controlled infrastructure

### Tools & Frameworks
- Wireshark  
- Zeek  
- Suricata  
- Zui (Zeek UI)  
- VirusTotal  
- Linux command-line utilities  
- MITRE ATT&CK Framework  

---

## 3. Evidence Collected

### Evidence Artifacts
- Network packet capture (PCAP)
- IDS/IPS alert logs (Suricata)
- Zeek HTTP, DNS, and connection logs
- Extracted malicious payloads (ISO, LNK, EXE)
- Hashes and metadata of extracted artifacts

> Detailed acquisition notes and hashes are documented in the `evidence-metadata/` directory.

---

## 4. Analysis & Findings

> Analysis sections will be populated incrementally as findings are validated.

### 4.1 Initial Indicators
Pending analysis.

### 4.2 Timeline Reconstruction
Pending analysis.

### 4.3 Host-Based Analysis
Pending analysis.

### 4.4 Network Analysis
Pending analysis.

### 4.5 Malware Behavior
Pending analysis.

---

## 5. Conclusion (Draft)
Pending investigation results.

---

## 6. Appendix
- Indicators of Compromise (IOCs)
- Detection Opportunities
- MITRE ATT&CK Mapping
