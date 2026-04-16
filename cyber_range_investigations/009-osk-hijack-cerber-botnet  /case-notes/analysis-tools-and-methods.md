# Analysis Tools and Methods

**Document Type:** Reference

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Purpose

This document enumerates the tools, platforms, queries, and methodologies used during the investigation. It serves as a reference for how analysis was conducted and does not contain findings or conclusions.

## Tools & Platforms

### SIEM / Log Analysis

- Splunk
  - Dataset: `index="botsv1"`
  - Used for:
    - Endpoint telemetry analysis (Sysmon / Windows logs)
    - Network log correlation (Fortigate UTM, Suricata)
    - Statistical aggregation and pivoting

### Endpoint Telemetry

- Sysmon (via XmlWinEventLog)
  - Event ID 1 (Process Creation)
  - Event ID 7 (Image Loaded)
  - Used for:
    - Process execution tracking
    - File path validation
    - Hash extraction
    - Network connection attribution

### Network Security Monitoring

- Fortigate UTM Logs
  - Used for:
    - Malware categorization (`appcat`)
    - Threat identification (`app`)
    - Network enrichment

- Suricata IDS
  - Used for:
    - Alert-based detection
    - Signature analysis (`alert.signature`)
    - Reconnaissance identification

### Threat Intelligence

- VirusTotal
  - Used for:
    - Hash reputation lookup
    - Malware family attribution
    - Vendor detection aggregation

### OSINT Sources

- Microsoft Documentation
  - Used to validate legitimate behavior of `osk.exe`
  - Confirmed expected file path and functionality

## Methods & Techniques

### 1. Baseline Validation (OSINT)

- Identified legitimate purpose of `osk.exe`
- Confirmed expected system path:
  - `C:\Windows\System32\osk.exe`
- Established baseline for anomaly detection

### 2. SIEM Querying and Pivoting

- Initial query:
  - `index="botsv1" sourcetype=xmlwineventlog "osk.exe"`
- Aggregation:
  - `| stats count`
- Pivoting fields:
  - `Image`
  - `User`
  - `Computer`
  - `SourceIp`
  - `DestinationIp`
  - `DestinationPort`

### 3. Anomaly Detection

- Identified non-standard execution path:
  - AppData directory with GUID structure
- Detected abnormal event volume (~49,608 events)

### 4. Network Behavior Analysis

- Isolated high-frequency communication port:
  - `DestinationPort=6892`
- Measured communication scope:
  - `| stats dc(DestinationIp)`
- Identified reconnaissance behavior via HTTP (port 80)

### 5. Cross-Log Correlation

- Pivoted from Sysmon → Fortigate UTM:
  - `index="botsv1" sourcetype=fortigate_utm dest_port=6892`
- Pivoted from Sysmon → Suricata:
  - `index="botsv1" sourcetype=suricata dest_ip=54.148.194.58 event_type=alert`

### 6. Hash Extraction and Identification

- Query:
  - `index="botsv1" sourcetype=xmlwineventlog EventCode=7 ImageLoaded="*osk.exe*"`
- Extracted SHA256 hash from `Hashes` field
- Submitted hash to VirusTotal for attribution

## Key Takeaways

- Effective investigations rely on pivoting between log sources  
- Field normalization is critical when correlating data across platforms  
- Combining endpoint telemetry with network and threat intelligence enables full attack lifecycle visibility  
