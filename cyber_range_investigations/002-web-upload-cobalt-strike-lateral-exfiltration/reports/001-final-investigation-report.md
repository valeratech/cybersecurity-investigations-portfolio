# Final Investigation Report

**Case Title:** Web Upload Abuse → Cobalt Strike C2 → Lateral Movement & Exfiltration  
**Case ID:** 002  
**Author:** Ryan Valera  
**Date Completed:** 2026-01-08  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

This investigation examined a suspected compromise involving a public-facing web application hosted by the organization. An Endpoint Detection and Response (EDR) alert identified a malicious file within the upload directory of a contact-us form.

Network forensic analysis revealed that the contact form was abused to upload a malicious ISO payload, which resulted in the execution of malware on an internal endpoint. The malware established command-and-control (C2) communications using the Cobalt Strike framework over HTTP, enabled lateral movement via SMB and RDP, and staged data for exfiltration from a web server directory.

All findings were derived exclusively from network telemetry provided by the CyberDefenders CyberRange.

## 2. Scope & Evidence

### Scope
- Network-based investigation only  
- No host-based disk or memory images provided  
- Analysis conducted **in situ** within the CyberRange VM  

### Evidence
- Network packet capture (PCAP)  
- Suricata IDS alerts  
- Zeek HTTP and connection logs  

Evidence handling and metadata are documented in:

evidence-metadata/001-evidence-register.md

## 3. Initial Access & Payload Delivery

### Entry Point
The attacker abused the organization’s public contact form:

`http://www.mindtech.net/contact.php`

The payload was delivered via an HTTP POST request using `multipart/form-data`.

### Delivered Payload
- **Filename:** `Urgent Support.iso`
- **MIME Type:** `application/x-cd-image`
- **Delivery Method:** Web upload via contact form

Packet-level inspection confirmed the file was successfully transferred to the server.

## 4. Malware Execution & Defense Evasion

Analysis of the ISO contents revealed a Windows shortcut file (`DOCUMENT.LNK`) containing an embedded PowerShell command.

### Observed Command

`Set-MpPreference -DisableRealtimeMonitoring 1; D:\ADOBE.exe`

This command disables Windows Defender real-time protection and executes a secondary payload, enabling post-exploitation activity.

## 5. Command and Control (C2)
### C2 Framework
Tool: Cobalt Strike

Detection Method: IDS alerts, Zeek telemetry, VirusTotal YARA matches

### C2 Infrastructure

- **IP Address**: `113.26.232.2`
- **Protocol**: `HTTP`
- **Port**: `80`
- **URI Pattern**: `/en_US/all.js`

Beacon traffic exhibited characteristics consistent with Cobalt Strike’s HTTP-based communication model.

## 6. Internal Lateral Movement

### Compromised Endpoint

**Internal IP**: `10.0.128.130`

This host was identified as the initially compromised internal system based on outbound C2 communications.

### Lateral Movement Techniques

- **SMB / SMB2**
  - Observed file access activity
  - IDS alerts indicating possible lateral tool transfer

- **RDP**
  - Multiple sessions observed between internal hosts

The final RDP session duration was approximately **137 seconds**.

7. Data Staging & Exfiltration Attempt
Due to outbound restrictions on the web server, the attacker staged data internally.

**Targeted Directory**: `\\WWW\wwwroot`

SMB traffic and exported objects indicated access to web server content consistent with data staging prior to exfiltration.

## 8. Timeline Overview (High-Level)

- Malicious ISO uploaded via contact form
- Payload executed on internal endpoint
- Windows Defender disabled
- Cobalt Strike beacon established
- SMB and RDP activity observed
- Web server data staged for exfiltration

A detailed timestamp-level timeline is documented within the analysis artifacts.

## 9. Conclusions

This investigation confirms a multi-stage intrusion involving:
- Web application abuse for initial access
- Malware delivery via ISO payload
- Defense evasion through PowerShell
- Persistent C2 via Cobalt Strike
- Lateral movement using SMB and RDP
- Staging of sensitive web content for exfiltration

All conclusions are supported by network-based evidence.

## 10. Appendix (Summary)

### Indicators of Compromise

- **External IP**: 113.26.232.2
- **Malicious file**: `Urgent Support.iso`
- **C2 URI**: `/en_US/all.js`

### ATT&CK Techniques (Observed)

- T1190 – Exploit Public-Facing Application
- T1105 – Ingress Tool Transfer
- T1059.001 – PowerShell
- T1071.001 – Web Protocols
- T1021.001 – Remote Services (RDP)
- T1570 – Lateral Tool Transfer

## 11. Notes
- This repository intentionally excludes restricted raw evidence.
- All analysis was conducted in accordance with CyberDefenders CyberRange access constraints.

**End of Report**
