# Timeline Reconstruction (UTC)

**Document Type:** Analysis

**Case ID:** 002-web-upload-cobalt-strike-lateral-exfiltration  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Overview

This document provides a chronological reconstruction of attacker activity based on network telemetry. All timestamps are normalized to UTC.

## Timeline

| Timestamp (UTC) | Event | Source | Notes |
|----------------|------|--------|------|
| TBD | Malicious ISO uploaded via contact form | HTTP (PCAP) | Initial access vector |
| TBD | Payload execution on internal host | HTTP / Artifact correlation | ISO → LNK → PowerShell |
| TBD | Windows Defender disabled | Command artifact | Defense evasion |
| TBD | Cobalt Strike beacon established | HTTP / Suricata alerts | External C2 communication |
| TBD | SMB activity observed | SMB traffic | Possible lateral movement |
| TBD | RDP sessions initiated | RDP traffic | Internal host movement |
| TBD | Data staging activity | SMB traffic | Access to \\WWW\wwwroot |

## Notes

- Timeline entries will be updated as timestamps are validated  
- All events are derived from network-based evidence  
- Correlation across HTTP, SMB, RDP, and IDS alerts is required for accuracy  
