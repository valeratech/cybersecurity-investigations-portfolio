# Investigation Report Template

**Case Title:**  
**Case ID:**  
**Date Created:**  
**Last Updated:**  
**Author:**  


## 1. Overview

### Objective
Describe the purpose of the investigation (e.g., identify initial access vector, analyze malware behavior, trace lateral movement, investigate suspicious network activity, etc.).

### Scenario Summary
Provide a brief description of the lab, challenge, or CyberRange environment.  
Include the source platform (SANS, CyberDefenders, SBT Labs, Cyberanges, self-hosted, etc.).

### Key Focus Areas
- Memory / Disk / Network Forensics  
- Threat Hunting  
- Malware Analysis  
- Endpoint Investigation  
- Incident Reconstruction  


## 2. Environment & Tools Used

### Environment Description
- OS versions  
- Network segments / topology  
- Hostnames or identifiers used in the scenario  

### Tools & Frameworks  
Examples (modify per case):

- Volatility / Rekall  
- Wireshark / TCPdump  
- Zeek / Suricata / Brim / Zui  
- Elastic / Splunk / Sysmon  
- KAPE / Eric Zimmerman tools  
- PowerShell / Python scripts  
- MITRE ATT&CK (TTP mapping)  


## 3. Evidence Collected

List all evidence sources used in the investigation.

### Evidence Artifacts
Examples:

- Memory dump (.raw, .vmem)  
- Disk image (.E01, .dd)  
- PCAP or packet captures  
- Zeek logs  
- Sysmon logs  
- Windows Event Logs (.evtx)  
- Registry / Prefetch / AmCache  
- Browser artifacts  
- Extracted malware samples (redacted if needed)  

Provide file names/paths if applicable.


## 4. Analysis & Findings

Break down your analysis logically. Subsections may include:

### 4.1 Initial Indicators  
Summaries of suspicious activity, alerts, or anomalies that initiated the investigation.

### 4.2 Timeline Reconstruction  
Document major events in chronological order:

- Authentication events  
- Process creation  
- Network connections  
- Persistence mechanisms  
- Privilege escalation  
- Data exfiltration indicators  

Include timestamps in UTC unless otherwise noted.

### 4.3 Host-Based Analysis  
Examples:

- Suspicious processes  
- Malicious binaries  
- File system changes  
- Registry modifications  
- Persistence mechanisms  
- Evidence of lateral movement  

### 4.4 Network Analysis  
Examples:

- Command-and-control traffic  
- Data exfiltration attempts  
- Internal recon or SMB activity  
- Anomalous JA3/JARM fingerprints  
- DNS patterns  

### 4.5 Memory Analysis (if applicable)  
Examples:

- Malicious processes/modules  
- Injected threads  
- Network connections in memory  
- Credential access artifacts  
- Malware configuration extraction  

### 4.6 Malware Behavior (if applicable)  
Examples:

- Execution behavior  
- Indicators from sandboxing or manual examination  
- Persistence actions  
- Payloads or encoded commands  
- Dropped files  

---
