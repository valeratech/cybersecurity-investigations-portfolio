# Case 003 — Alert Triage: Signatures & Filters

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document records the structured triage of IDS alerts observed in the PCAP. The goal is to identify patterns of malicious activity, isolate the primary attacker IP, and determine whether reconnaissance or exploitation occurred against the HR web server.

This analysis provides the foundation for:
- Attacker attribution
- Reconnaissance tooling identification
- Exploitation confirmation

## Data Source
- **Evidence ID:** E-001  
- **Type:** Network packet capture (PCAP)  
- **Coverage:** Inbound and internal traffic involving `hr.compliantsecure.store` and internal hosts

## Alert Aggregation Methodology

Alerts were grouped and counted by the field:
`alert.signature`

This approach highlights:
- Repeated attacker behavior
- High-signal signatures over background noise
- Web exploitation vs. generic internet scanning

## Alert Signature Summary (Selected)

The following alert signatures were observed and considered relevant to the investigation:

- `GPL WEB_SERVER printenv access`
- `GPL WEB_SERVER /~root access`
- `GPL WEB_SERVER global.asa access`
- `ET WEB_SERVER WEB-PHP phpinfo access`
- `ET WEB_SERVER WebShell Generic - ASP File Uploaded`
- `ET INFO User-Agent (python-requests) Inbound to Webserver`
- `ET SCAN RDP Connection Attempt from Nmap`
- `ET SCAN Potential VNC Scan 5800-5820`
- `ET SCAN Suspicious inbound to PostgreSQL port 5432`

Numerous additional alerts related to reputation feeds (CINS, Spamhaus, DShield) were observed but treated as **contextual noise** unless correlated with confirmed attacker behavior.

## High-Confidence Web Reconnaissance Indicators

### GPL WEB_SERVER printenv access
- **Category:** Access to potentially vulnerable web application
- **Behavior:** Attempts to access environment variables
- **Assessment:** Strong indicator of web server reconnaissance

### GPL WEB_SERVER /~root access
- **Category:** Attempted Information Leak
- **Behavior:** Attempts to access legacy or sensitive directories
- **Assessment:** Directory enumeration behavior

These alerts repeatedly originated from the same source IP and targeted the HR web server over HTTP.

## Attacker IP Identification

### Correlated Attributes
- **Source IP:** `3.68.76.39`
- **Destination IP:** `10.10.3.115`
- **Destination Port:** `80`
- **Protocol:** HTTP

This IP was consistently associated with:
- Web directory probing
- Environment enumeration
- Follow-on scanning activity

**Conclusion:**  
`3.68.76.39` is identified as the primary attacker IP responsible for reconnaissance and exploitation attempts against the HR web server.

## Scan Activity & Tool Attribution

### Relevant Signature
`ET SCAN RDP Connection Attempt from Nmap`

This alert indicates an RDP connection attempt pattern consistent with **Nmap service scanning**.

Subsequent packet inspection confirmed:
- RDP negotiation cookies containing `mstshash=nmap`
- TCP SYN behavior aligned with automated scanning

**Assessment:**  
The attacker used **Nmap** for service and port reconnaissance following initial web probing.

## Filters Used (Investigator)

### Zui / Brim
- Group by: `alert.signature`
- Filter by source IP:
`src_ip == 3.68.76.39`

### Wireshark
- Focus on web traffic:
`http && ip.src == 3.68.76.39`

- Scan-related confirmation:
`tcp.port == 3389`

## Key Findings from Alert Triage

- The activity is **targeted**, not opportunistic background scanning
- Reconnaissance precedes exploitation behavior
- Alerts escalate from directory enumeration to upload-based exploitation
- The same source IP transitions from web probing to internal service scanning

## Analytical Conclusion

Alert triage confirms a deliberate attack lifecycle:
1. Web reconnaissance against HR application
2. Enumeration of server environment and directories
3. Service and port scanning using Nmap
4. Progression toward exploitation (confirmed in subsequent analysis)

## Next Investigative Pivot

Following confirmation of malicious reconnaissance:
- Packet-level inspection was initiated to identify scanning tools
- HTTP streams were analyzed for file upload activity
- Correlation with Zeek `files.log` was performed to validate exploitation

**Next file:**  
`analysis/002-network-scan-and-recon-attribution.md`
