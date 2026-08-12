# Case 003 — SMB Share Enumeration & Sensitive Data Discovery

**Document Type:** Analysis  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes SMB share enumeration activity following authenticated lateral movement. It identifies accessible shared directories, highlights sensitive data exposure, and establishes context for the subsequent directory listing.

## Data Sources
- PCAP (E-001)
- Wireshark SMB2 protocol analysis
- Zeek SMB mapping and file metadata

All timestamps referenced are treated as **UTC**.

## Enumeration Context

Following successful SMB authentication using recovered domain credentials, the attacker enumerated file shares hosted on the internal file server.

### Target System
- **Hostname:** `FILESERVER01[.]ad[.]compliantsecure[.]store`
- **IP Address:** `10[.]10[.]11[.]216`
- **Service:** `SMB (TCP/445)`

### Share Enumerated
This share contained multiple directories with business-critical and potentially regulated data.

## SMB Enumeration Activity
### Enumeration Method

- SMB2 Find requests issued against the Shares directory
- Responses returned directory listings without access denials
- Activity occurred within minutes of successful authentication

### Confirmed Enumeration Timestamp
`2025-05-20 19:15:08Z`

## Discovered Directories

The following directories were identified during SMB enumeration:

- `Documents`
- `Finance`
- `HR`
- `IT`
- `Programs`

The observed SMB `Find` response returned five directory names in the share listing.

## Observed Access Scope

- Michael's authenticated SMB session successfully enumerated entries in the observed share

## Relationship to Subsequent SMB Activity

This enumeration directly preceded the SMB directory listing that named individual files.

Key observations:

- Enumeration established attacker awareness of valuable data locations
- Subsequent SMB Find responses included file names of interest
- PDF and document files were identified shortly after directory discovery

This step represents the share-to-contents transition within the internal network.

## Next Investigative Pivot

Following directory discovery:

- Identify the first filenames observed in the SMB listing
- Determine whether SMB read/open operations are recorded
- Assess whether SMB activity can be correlated with tunnel-related traffic
- Determine the earliest filename observed in the SMB listing

**Next file**:
`analysis/011-smb-share-enumeration-and-file-discovery.md`
