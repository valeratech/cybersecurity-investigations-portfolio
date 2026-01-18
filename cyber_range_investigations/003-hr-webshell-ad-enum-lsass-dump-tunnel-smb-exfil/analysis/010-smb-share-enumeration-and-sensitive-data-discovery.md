# Case 003 — SMB Share Enumeration & Sensitive Data Discovery

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes SMB share enumeration activity following authenticated lateral movement. It identifies accessible shared directories, highlights sensitive data exposure, and establishes context for subsequent data exfiltration.

## Data Sources
- PCAP (E-001)
- Wireshark SMB2 protocol analysis
- Zeek SMB mapping and file metadata

All timestamps referenced are treated as **UTC**.

## Enumeration Context

Following successful SMB authentication using recovered domain credentials, the attacker enumerated file shares hosted on the internal file server.

### Target System
- **Hostname:** `FILESERVER01.ad.compliantsecure.store`
- **IP Address:** `10.10.11.216`
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

These directories indicate broad access permissions and represent a high-value data exposure surface.

## Sensitive Data Exposure Assessment
###Risk Indicators

- Presence of HR and Finance directories implies access to PII and financial records
- IT and Programs directories may contain infrastructure documentation, scripts, or credentials
- No additional authentication challenges observed during enumeration

### Security Implications

- Over-permissive SMB share access
- Lack of network segmentation between web infrastructure and internal file servers
- Domain user account granted excessive read access across multiple departments

## Relationship to Exfiltration Phase

This enumeration phase directly preceded confirmed file access and data exfiltration activity.

Key observations:

- Enumeration established attacker awareness of valuable data locations
- Subsequent SMB Find responses included file names of interest
- PDF and document files were identified shortly after directory discovery

This step represents the reconnaissance-to-exfiltration transition within the internal network.

## Next Investigative Pivot

Following directory discovery:

- Identify first accessed files
- Confirm read/open operations over SMB
- Correlate file access with tunnel traffic
- Determine earliest exfiltrated artifact

**Next file**:
`analysis/011-smb-file-access-and-data-exfiltration.md`
