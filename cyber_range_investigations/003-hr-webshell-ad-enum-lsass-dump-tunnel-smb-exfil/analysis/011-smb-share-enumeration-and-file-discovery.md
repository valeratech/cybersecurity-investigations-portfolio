# Case 003 — SMB Share Enumeration & File Discovery

**Document Type:** Analysis  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes the SMB directory listing returned after share enumeration and records the filenames it exposed. It establishes the sequence from directory discovery to filename identification.

## Data Sources
- PCAP (E-001)
- Wireshark SMB2 protocol analysis
- Zeek SMB file metadata

All timestamps referenced are treated as **UTC**.

## Context

Following authenticated SMB access and share enumeration, the SMB session returned a directory listing naming individual files. This phase marks the transition from share discovery to filename discovery.

### Target System
- **Hostname:** `FILESERVER01[.]ad[.]compliantsecure[.]store`
- **IP Address:** `10[.]10[.]11[.]216`
- **Service:** `SMB (TCP/445)`

### Authentication Context
- **Account Used:** `michael@ad[.]compliantsecure[.]store`
- **Access Method:** Credential reuse following LSASS dump extraction

## SMB Directory Listing

### Enumeration Method
- SMB2 `Find` responses returned file listings within the `Shares` directory
- The listing revealed document names; the response returned STATUS_SUCCESS
- The listing followed the share enumeration in the same SMB session

### Observed File Types
- PDF documents
- Microsoft Office files (XLS, DOCX)
- Template and policy documentation

## First PDF Observed

### Earliest PDF in the Listing
`company_policy_manual.pdf`

This file was the earliest PDF named in the SMB directory listing. Its appearance establishes that the filename was returned in the SMB directory listing; it does not establish that the file was opened, read, or transferred.

## Listing Timing

### Observed Timestamp
`2025-05-20 19:15:08Z`

This timestamp is that of the SMB `Find` response containing the file name. It is the earliest surviving record in which that filename appears.

## What the Surviving Evidence Records

Key observations:
- The directory listing was returned over an authenticated SMB session
- The listing named five entries, of which `company_policy_manual.pdf` is the first PDF
- No SMB `Read`, no `Create` with read intent, and no transferred bytes appear in the surviving notes
- No correlation between the tunnel-related connection and any SMB operation is recorded

## Security Impact Assessment

- The SMB directory listing returned names of confidential policy documentation
- Attacker demonstrated ability to enumerate and selectively target files
- Domain credentials enabled unrestricted read access across departments

This confirms **unauthorized authenticated access and enumeration**. Whether any document was read or removed is not established by the surviving evidence.

## Investigation Status

At this stage, the investigation has confirmed:
- Initial access via webshell
- Credential harvesting via LSASS dump
- Lateral movement into internal systems
- Enumeration of sensitive directories
- Enumeration of sensitive filenames

## Next Investigative Pivot

Remaining investigative objectives:
- Identify additional filenames observed in SMB listings
- Determine whether any file-transfer volume is recorded
- Assess whether tunnel-related traffic can be correlated with SMB operations
- Summarize breach impact and attacker objectives

**Next file:**  
`analysis/012-impact-assessment-and-investigation-summary.md`
