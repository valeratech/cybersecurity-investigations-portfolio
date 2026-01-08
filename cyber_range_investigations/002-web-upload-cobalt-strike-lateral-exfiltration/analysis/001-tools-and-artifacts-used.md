# Tools, Platforms, Frameworks, and Artifacts Used

**Case ID:** 002  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

This document enumerates all tools, applications, frameworks, websites, protocols, commands, and file artifacts explicitly used or referenced during the investigation.  
No analysis, findings, or conclusions are included in this document.


## Tools & Applications Used

### Network & Packet Analysis

- **Wireshark**
  - Packet-level inspection
  - TCP stream following
  - Export Objects (HTTP, SMB)
  - Conversations statistics
  - Protocol Hierarchy statistics

- **Zeek**
  - HTTP logs
  - File extraction metadata
  - Connection metadata
  - Log fields such as `_path`, `id.orig_h`, `orig_filenames`

- **Suricata**
  - IDS/IPS alerting
  - Signature-based detection
  - Stream anomaly detection

- **Zui (Zeek UI)**
  - Log exploration dashboard
  - Alert filtering
  - Field counting (e.g., count by field)
  - Correlation of alerts, flows, and files

## Security & Malware Analysis Platforms

- **VirusTotal**
  - IP reputation checks
  - File hash analysis
  - Community YARA rule matches
  - Malware family identification

- **THOR APT Scanner (via YARA signatures)**
  - Detection of Cobalt Strike artifacts

## Command-Line Tools & Commands

### Linux Command-Line Utilities

**strings**

  `strings -e l DOCUMENT.LNK`
