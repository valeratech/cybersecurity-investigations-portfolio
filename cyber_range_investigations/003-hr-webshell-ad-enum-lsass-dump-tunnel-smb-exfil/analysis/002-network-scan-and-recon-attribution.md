# Case 003 — Network Scan & Reconnaissance Attribution

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document attributes the observed reconnaissance and service scanning activity to a specific tool by correlating IDS alerts with packet-level protocol artifacts. The objective is to move beyond alert-based suspicion and provide direct evidence of the scanning utility used by the attacker.

## Data Sources
- PCAP (E-001)
- Suricata IDS alerts
- Wireshark packet inspection

All timestamps referenced in this document are treated as **UTC**.

## Reconnaissance Indicators

During alert triage, multiple signatures suggested active service discovery, including:
- RDP connection attempts
- Scanning of non-web services (PostgreSQL, VNC)
- Broad probing behavior inconsistent with normal web traffic

Of particular interest was an alert explicitly referencing a known scanning tool.

## IDS-Based Attribution

### Relevant Alert
- **Signature:** `ET SCAN RDP Connection Attempt from Nmap`
- **Category:** Detection of a Network Scan
- **Source IP:** `3.68.76.39`
- **Destination IP:** `10.10.3.115`
- **Destination Port:** `3389/TCP`
- **Timestamp:** 2025-05-20 18:20:46Z

This alert strongly suggested the use of **nmap** for reconnaissance; however, packet-level confirmation was required.

## Packet-Level Validation

### RDP Negotiation Artifact
Wireshark inspection of the associated RDP connection attempt revealed the following artifact:

- **RDP Cookie:** `mstshash=nmap`
- **Protocol:** RDP Negotiation Request
- **Requested Capabilities:** TLS, CredSSP, Early User Authorization

The `mstshash` value is a well-known identifier used by **nmap** during RDP scanning and is commonly observed when the `rdp-*` NSE scripts or service detection routines are used.

## Analytical Assessment

The presence of:
- IDS alerts explicitly naming nmap
- An RDP negotiation cookie containing `mstshash=nmap`
- Consistent scanning behavior across multiple services

Provides high-confidence attribution that the attacker used **nmap** to perform service and port scanning against the target infrastructure.

This confirms that reconnaissance was:
- Intentional
- Automated
- Conducted prior to exploitation

## Impact on Investigation Flow

Attributing reconnaissance to nmap establishes:
- The attacker followed a structured attack lifecycle
- Service discovery preceded exploitation
- The web server was likely identified as a viable pivot point early in the attack

This attribution justified further analysis of:
- HTTP traffic for exploitation attempts
- File upload activity
- Post-exploitation command execution

## Next Investigative Pivot

Following confirmation of reconnaissance tooling, the investigation pivoted to:
- Identifying successful exploitation events
- Detecting file upload activity consistent with webshell deployment
- Correlating IDS alerts with Zeek file metadata and HTTP streams

**Next file:**  
`analysis/003-webshell-upload-and-http-exploitation.md`
