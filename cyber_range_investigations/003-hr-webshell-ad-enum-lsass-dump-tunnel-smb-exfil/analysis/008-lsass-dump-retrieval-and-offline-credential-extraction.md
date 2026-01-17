# Case 003 — LSASS Dump Retrieval & Offline Credential Extraction

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes how the attacker retrieved the LSASS memory dump from the compromised host, extracted credential material offline, and obtained plaintext domain credentials. This step bridges credential access with authenticated lateral movement.

## Data Sources
- PCAP (E-001)
- Wireshark HTTP object export
- Webshell file browser activity
- Offline credential extraction artifacts

All timestamps referenced below are treated as **UTC**.

## LSASS Dump Retrieval

### Retrieval Method
After generating the LSASS dump on the compromised web server, the attacker used the webshell’s file browsing functionality to download the dump file.

### Observed HTTP Response
Wireshark inspection confirmed the download via an HTTP response with the following characteristics:
- **Content-Type:** `application/force-download`
- **Filename:** `lsass.dmp`
- **Delivery Mechanism:** Webshell file editor/browser endpoint

### Confirmed Timestamp
`2025-05-20 18:48:00Z`

This timestamp marks the point at which credential material left the compromised system.

## Offline Credential Extraction

Once retrieved, the attacker performed offline analysis of the dump file rather than extracting credentials directly on the host.

### Extraction Tool Used
pypykatz

### Command Pattern
`pypykatz lsa minidump lsass_20250520.dmp > pypykatz_output.txt`

This tool parses LSASS memory dumps to recover:
- NTLM password hashes
- Kerberos keys
- Cached credentials
- DPAPI master keys

## Extracted Credential Evidence

Analysis of the parsed output revealed a domain user account with recoverable credential material.

### Identified Account
- **Username:** `michael`
- **Domain:** `AD`
- **Logon Server:** `DC01`

### Extracted Hash
`michael:2b52d3f28841abe8c3c1d0568d945fa9`

This NT hash was suitable for offline password cracking.

## Password Cracking Activity

### Tool Used
John the Ripper

### Cracking Method
- Hash format: NT
- Wordlist-based attack

### Result
**Username**: `michael`

**Plaintext Password**: `MyPassw0rd123@`

The successful crack confirms weak password hygiene and directly enabled authenticated SMB access observed later in the investigation.

## Analytical Assessment

Key observations:
- Credential extraction was conducted entirely offline
- No further interaction with the compromised host was required
- The attacker avoided generating additional security telemetry during cracking
- Obtained credentials were reused for SMB authentication shortly after

This demonstrates a clean separation between **credential harvesting** and **credential abuse**, a common tradecraft pattern.

## Impact on Investigation Flow

Recovered credentials explain:
- Authenticated SMB session establishment
- Access to sensitive file shares
- Subsequent directory enumeration and data exfiltration

This step represents the transition from **post-exploitation** to **lateral movement**.

## Next Investigative Pivot

Following credential recovery:
- Correlate cracked credentials with SMB authentication events
- Identify first authenticated access timestamp
- Track directory enumeration and file access activity

**Next file:**  
`analysis/009-authenticated-smb-access-and-lateral-movement.md`
