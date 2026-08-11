# Case 003 — LSASS Dump Retrieval & Offline Credential Extraction

**Document Type:** Analysis  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes how the attacker retrieved the LSASS memory dump from the compromised host, and records the investigator's offline extraction of credential material from that dump. This step bridges credential access with authenticated lateral movement.

## Data Sources
- PCAP (E-001)
- Wireshark HTTP object export
- Webshell file browser activity
- Offline credential extraction artifacts

All timestamps referenced below are treated as **UTC**.

## LSASS Dump Retrieval

### Retrieval Method
After generating the LSASS dump on the compromised web server, the attacker used the webshell's file browsing functionality to download the dump file.

### Observed HTTP Response
Wireshark inspection confirmed the download via an HTTP response with the following characteristics:
- **Content-Type:** `application/force-download`
- **Filename:** `lsass.dmp`
- **Delivery Mechanism:** Webshell file editor/browser endpoint

### Confirmed Timestamp
`2025-05-20 18:48:00Z`

This timestamp marks the point at which credential material left the compromised system.

## Analyst Credential Extraction

The 18:48 retrieval is the last attacker action evidenced in this section. The credential extraction and password-cracking steps below were performed by the investigator against the exported dump as part of the analysis workflow.

### Extraction Tool Used
pypykatz (investigator)

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
`michael:2b52d3f2...`

*NT hash truncated; the full value is withheld as credential material.*

This NT hash was suitable for offline password cracking.

## Analyst Password Cracking Activity

### Tool Used
John the Ripper

### Cracking Method
- Hash format: NT
- Wordlist-based attack

### Result
**Username**: `michael`

**Plaintext Password**: `<REDACTED>`  
*(14 characters; dictionary word + leetspeak substitution + trailing symbol - recovered from a standard wordlist attack in under a minute)*

The recovered password demonstrates weak password hygiene. The same account authenticated over SMB later in the capture.

## Analytical Assessment

Key observations:
- Michael's credentials were recovered from the retrieved dump during analysis
- The same account authenticated over SMB shortly after the retrieval

The surviving notes record retrieval of `lsass.dmp` at 18:48:00 UTC and later show SMB authentication as `michael@ad[.]compliantsecure[.]store` at 19:14:38 UTC. The attacker activity between those events is not recorded in the surviving evidence.

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
