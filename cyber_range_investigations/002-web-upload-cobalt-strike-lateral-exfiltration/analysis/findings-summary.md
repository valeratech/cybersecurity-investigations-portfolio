# Findings Summary

**Document Type:** Findings

**Case ID:** 002-web-upload-cobalt-strike-lateral-exfiltration  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Overview

This document consolidates all confirmed findings derived from network-based analysis conducted during the investigation. All findings are supported by validated evidence and correlate across multiple analysis artifacts.

## Finding 1 – Initial Access via Web Application Upload

### Observation
HTTP traffic analysis identified a POST request to:

`http[:]//www[.]mindtech[.]net/contact[.]php`

The request used `multipart/form-data` to upload a file.

### Evidence
- HTTP POST request observed in PCAP  
- File transfer confirmed via packet reconstruction  

### Conclusion
The attacker abused the public-facing contact form to upload a malicious payload, establishing initial access into the environment.

## Finding 2 – Malicious Payload Delivery (ISO File)

### Observation
The uploaded file was identified as:

- Filename: `Urgent Support.iso`  
- MIME Type: `application/x-cd-image`  

### Evidence
- HTTP file upload transaction  
- Extracted file metadata from network stream  

### Conclusion
The attacker delivered a malicious ISO archive as the initial payload via web upload.

## Finding 3 – Execution via LNK and PowerShell

### Observation
The ISO contained a Windows shortcut file (`DOCUMENT.LNK`) with an embedded PowerShell command:

`Set-MpPreference -DisableRealtimeMonitoring 1; D:\ADOBE.exe`

### Evidence
- Extracted LNK artifact from network stream  
- Decoded command string from artifact  

### Conclusion
The payload executed a PowerShell command to disable Windows Defender and launch a secondary executable, enabling defense evasion and execution of malicious code.

## Finding 4 – Command-and-Control (C2) Beaconing

### Observation
High-frequency HTTP traffic was observed between an internal host and:

`113[.]26[.]232[.]2`

Repeated requests followed a consistent pattern:

- URI: `/en_US/all.js`  
- Response: `HTTP/1.1 200 OK` with minimal or zero content  

### Evidence
- Suricata alert: ET MALWARE Cobalt Strike Beacon Observed  
- Zeek HTTP logs  
- Packet-level stream inspection  
- SHA-256 of the delivered payload: `935492b3714f140ff4567c14fe0fc13cba6f5df13a2be8a8b14912f2da24d475`  
- VirusTotal community YARA match (THOR APT Scanner):
  `CobaltStrike_Resources_Artifact64_v3_14_to_v4_x`, 12 / 60 detections  

### Conclusion
The compromised system established persistent command-and-control communications with external infrastructure. The network behaviour is consistent with Cobalt Strike Beacon activity, and the delivered payload was independently identified as a Cobalt Strike artifact by rule-based analysis of its hash.

## Finding 5 – Identification of Compromised Internal Host

### Observation
Outbound C2 communication originated from:

`10[.]0[.]128[.]130`

### Evidence
- Alert filtering by destination IP  
- Correlation of internal source IP to C2 traffic  

### Conclusion
The internal host `10[.]0[.]128[.]130` is confirmed as the initially compromised endpoint.

## Finding 6 – Lateral Movement via SMB and RDP

### Observation
Network activity indicates internal communication between hosts using:

- SMB / SMB2 protocols  
- RDP sessions  

Associated alerts include:

- ET POLICY SMB2 NT Create AndX Request For a DLL File  
- NETBIOS SMB IPC$ access alerts  

### Evidence
- Suricata SMB-related alerts  
- TCP session analysis  
- RDP session tracking  

### Conclusion
The attacker performed lateral movement within the internal network using SMB for file transfer and RDP for remote access.

## Finding 7 – Internal Transfer for Attempted Exfiltration

### Observation
SMB traffic indicates access to the web server directory:

`\\WWW\wwwroot`

Wireshark SMB object evidence showed the compromised endpoint accessing content
under this path on the web server. The CyberRange confirms that data was
transferred over SMB to the compromised endpoint for attempted exfiltration.

### Evidence
- SMB file access activity  
- Extracted objects from PCAP  
- Directory access patterns  

### Conclusion
Web server content was transferred internally over SMB to the compromised
endpoint for attempted exfiltration.

## Attack Chain Summary

1. Web application abuse (contact form upload)  
2. Malicious ISO payload delivery  
3. Execution via LNK and PowerShell  
4. Defense evasion (Windows Defender disabled)  
5. Cobalt Strike C2 established over HTTP  
6. Lateral movement via SMB and RDP  
7. Internal transfer of web server content for attempted exfiltration  

## Current Assessment

- The attack is confirmed as a multi-stage intrusion leveraging web application abuse for initial access.  
- Cobalt Strike was used for command-and-control and post-exploitation activity.  
- Internal network compromise and lateral movement were successfully achieved.  
- The retained evidence establishes internal SMB transfer for attempted
  exfiltration but does not establish that the data subsequently left the network.
