# Case 003 — Authenticated SMB Access & Lateral Movement

**Document Type:** Analysis  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes authenticated lateral movement over SMB following credential compromise. It correlates recovered credentials with SMB session establishment, share access, and initial directory enumeration on the internal file server.

## Data Sources
- PCAP (E-001)
- Wireshark SMB2 protocol analysis
- Zeek SMB metadata
- Previously recovered credentials

All timestamps referenced are treated as **UTC**.

## Preconditions for Lateral Movement

Prior investigative steps confirmed:
- Successful recovery of plaintext domain credentials
- Valid domain account: `michael@ad[.]compliantsecure[.]store`
- Credentials cracked offline and not tested interactively on the web server

These conditions enabled clean authentication against internal services.

## SMB Authentication Event

### Target System
- **Hostname:** `FILESERVER01[.]ad[.]compliantsecure[.]store`
- **IP Address:** `10[.]10[.]11[.]216`
- **Service:** `SMB (TCP/445)`

### Source System
- **Compromised Host:** HRWEBSERVER
- **IP Address:** 10[.]10[.]3[.]115

### Authentication Timestamp
`2025-05-20 19:14:38Z`

### Protocol Details
- **Protocol:** SMB2
- **Command:** `Tree Connect`
- **Authentication Context:** `michael@ad[.]compliantsecure[.]store`
- **Session Type:** Authenticated, signed SMB session

The SMB Tree Connect request confirms credential reuse rather than anonymous or guest access.

### Initial Share Access

`\\10[.]10[.]11[.]216\IPC$`

This connection represents the initial authenticated foothold on the file server and precedes access to user-facing shares.

## Transition to File Share Enumeration

Following successful authentication:

- The attacker pivoted from IPC$ to shared directories

- SMB Find requests were issued against the Shares directory

- The observed SMB `Find` response in frame 32375 returned `STATUS_SUCCESS` for the authenticated session

This activity confirms successful lateral movement, not just credential testing.

## Analytical Assessment

Key findings:

- SMB authentication occurred shortly after tunnel establishment

- Authentication used cracked credentials rather than system account tokens

- SMB signing was enabled, indicating legitimate protocol negotiation

- No brute-force or failed login attempts were observed

This behavior aligns with credential-based lateral movement, rather than exploitation-based movement.

## Security Implications

- Domain credentials extracted from a single system enabled access to sensitive internal resources

- Weak password hygiene significantly increased the blast radius

## Next Investigative Pivot

Following authenticated SMB access:

- Enumerate directories and filenames returned in SMB listings

- Identify sensitive data exposure

- Determine whether SMB read activity is recorded alongside the Find responses

- Determine the first filenames disclosed

Next file:
`analysis/010-smb-share-enumeration-and-sensitive-data-discovery.md`
