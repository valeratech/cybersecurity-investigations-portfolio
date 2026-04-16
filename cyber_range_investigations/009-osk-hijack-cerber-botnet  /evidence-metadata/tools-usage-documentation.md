# Tools Usage Documentation

**Document Type:** Evidence Metadata

**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Purpose

This document records how each tool and data source was used during the investigation, including scope of use, query methods, and type of evidence derived. This ensures reproducibility and traceability of analysis steps.

## Tool Usage Breakdown

### Splunk (SIEM)

**Dataset:** `index="botsv1"`

**Usage:**
- Queried Sysmon and Windows Event Logs
- Identified process execution activity
- Performed statistical aggregation (`stats count`, `dc()`)
- Pivoted across multiple log sources

**Key Queries:**
- `index="botsv1" sourcetype=xmlwineventlog "osk.exe"`
- `index="botsv1" sourcetype=xmlwineventlog "osk.exe" | stats count`
- `index="botsv1" sourcetype=xmlwineventlog "osk.exe" DestinationPort=6892 DestinationIp=* | stats dc(DestinationIp)`

**Evidence Produced:**
- Process execution data  
- Network connection telemetry  
- Event volume metrics  

### Sysmon (Windows Endpoint Telemetry)

**Event IDs Used:**
- Event ID 1 (Process Creation)
- Event ID 7 (Image Loaded)

**Usage:**
- Identified execution path of suspicious binary  
- Confirmed binary load into memory  
- Extracted SHA256 hash  
- Correlated network activity to process  

**Evidence Produced:**
- File path (`Image`)  
- Hash values (`Hashes`)  
- Network fields (`DestinationIp`, `DestinationPort`)  

### Fortigate UTM Logs

**Usage:**
- Correlated outbound network activity  
- Identified malware classification via enrichment fields  

**Key Query:**
- `index="botsv1" sourcetype=fortigate_utm dest_port=6892`

**Evidence Produced:**
- Malware category (`Botnet`)  
- Specific threat name (`Cerber.Botnet`)  

### Suricata IDS

**Usage:**
- Identified IDS alerts associated with suspicious traffic  
- Confirmed reconnaissance behavior  

**Key Query:**
- `index="botsv1" sourcetype=suricata dest_ip=54.148.194.58 event_type=alert`

**Evidence Produced:**
- Alert signature:
  - `ET POLICY Possible External IP Lookup ipinfo.io`  

### VirusTotal (Threat Intelligence)

**Usage:**
- Submitted SHA256 hash for reputation analysis  
- Identified malware family and classification  

**Evidence Produced:**
- Malware family: Cerber  
- Detection consensus across vendors  

### OSINT (Microsoft Documentation)

**Usage:**
- Validated legitimate function of `osk.exe`  
- Confirmed expected system file path  

**Evidence Produced:**
- Baseline behavior for anomaly detection  

## Methodological Notes

- All analysis performed using read-only queries  
- No direct modification or execution of suspect binaries  
- Cross-source correlation used to validate findings  
- Field normalization applied when pivoting between log sources  

## Reproducibility

All steps, queries, and tool usage documented here can be reproduced within the Security Blue Team CyberRange environment using the `botsv1` dataset and associated log sources.
