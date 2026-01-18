# Case 003 — SMB File Access & Data Exfiltration

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes SMB file access activity following share enumeration and confirms data exfiltration of sensitive documents. It establishes the sequence from directory discovery to file identification and initial data theft.

## Data Sources
- PCAP (E-001)
- Wireshark SMB2 protocol analysis
- Zeek SMB file metadata
- Tunnel traffic correlation

All timestamps referenced are treated as **UTC**.

## Context

After authenticating to the internal file server and enumerating shared directories, the attacker began identifying and accessing individual files of interest. This phase marks the transition from discovery to data theft.

### Target System
- **Hostname:** `FILESERVER01.ad.compliantsecure.store`
- **IP Address:** `10.10.11.216`
- **Service:** `SMB (TCP/445)`

### Authentication Context
- **Account Used:** `michael@ad.compliantsecure.store`
- **Access Method:** Credential reuse following LSASS dump extraction

## SMB File Enumeration

### Enumeration Method
- SMB2 `Find` responses returned file listings within the `Shares` directory
- File metadata revealed document names without access denial
- Activity followed immediately after directory enumeration

### Observed File Types
- PDF documents
- Microsoft Office files (XLS, DOCX)
- Template and policy documentation

## Confirmed Exfiltrated File

### First Identified Exfiltrated Artifact
`company_policy_manual.pdf`

This file was the earliest PDF observed during SMB file enumeration and is the first confirmed indicator of sensitive document access.

## Exfiltration Timing

### Observed Timestamp
`2025-05-20 19:15:08Z`

This timestamp corresponds with SMB `Find` responses that included the file name and indicates the earliest point at which the attacker identified and accessed the document.

## Exfiltration Mechanism

Key observations:
- File access occurred over authenticated SMB
- Data transfer was facilitated via the previously established tunnel
- No additional malware execution was required on the file server
- The tunnel enabled covert data movement without direct external SMB exposure

## Security Impact Assessment

- Confidential policy documentation was exposed
- Attacker demonstrated ability to enumerate and selectively target files
- Tunnel-based exfiltration bypassed perimeter monitoring
- Domain credentials enabled unrestricted read access across departments

This confirms a **successful data breach**, not merely attempted access.

## Investigation Status

At this stage, the investigation has confirmed:
- Initial access via webshell
- Credential harvesting via LSASS dump
- Lateral movement into internal systems
- Enumeration of sensitive directories
- Confirmed exfiltration of sensitive data

## Next Investigative Pivot

Remaining investigative objectives:
- Identify additional files accessed or exfiltrated
- Determine total data volume transferred
- Correlate tunnel traffic with SMB reads
- Summarize breach impact and attacker objectives

**Next file:**  
`analysis/012-impact-assessment-and-investigation-summary.md`
