# Case 003 — Internal Host Targeting & SMB Discovery

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes how the attacker transitioned from domain enumeration to targeting a specific internal host for further exploration. It confirms SMB-based discovery activity and identifies the file server selected for share enumeration.

## Data Sources
- PCAP (E-001)
- Wireshark SMB2 protocol analysis
- Zeek SMB mapping logs

All timestamps referenced below are treated as **UTC**.

## Transition from AD Enumeration to Host Targeting

After completing Active Directory enumeration, the attacker possessed sufficient information to identify domain-joined systems of interest. Network traffic following the PowerShell enumeration revealed SMB communication initiated from the compromised web server toward an internal file server.

## Target Host Identified

SMB session setup and tree connect requests revealed the following target:

- **Hostname:** `FILESERVER01.ad.compliantsecure.store`
- **IP Address:** `10.10.11.216`
- **Service:** SMB over TCP/445

This system was selected for further exploration, indicating it was assessed as a high-value target for sensitive data access.

## SMB Discovery Evidence

### Initial SMB Session Setup
Wireshark analysis revealed SMB2 Session Setup requests originating from the compromised host:

- **Source:** `10.10.3.115` (HRWEBSERVER)
- **Destination:** `10.10.11.216` (FILESERVER01)
- **Protocol:** SMB2
- **Authentication Context:** Domain machine account (`HRWEBSERVER$`)

This indicates authenticated domain-level access was already in place prior to credential harvesting.

## Share Enumeration Activity

Subsequent SMB2 traffic included Tree Connect requests targeting administrative and IPC shares:

`\\FILESERVER01.ad.compliantsecure.store\IPC$`

This is a common initial step to:
- Validate connectivity
- Enumerate available shares
- Prepare for directory listing operations

## Zeek Correlation

Zeek SMB mapping logs corroborated packet-level findings:

- **Mapped Path:** `\\FILESERVER01.ad.compliantsecure.store\IPC$`
- **Timestamp:** 2025-05-20 18:45Z (approximate)
- **Initiator:** `10.10.3.115`

This correlation confirms that the SMB activity was not incidental but part of a deliberate discovery process.

## Analytical Assessment

The observed behavior demonstrates:
- A logical progression from AD enumeration to host targeting
- Selection of a file server likely to contain sensitive organizational data
- Use of SMB discovery techniques to enumerate accessible resources

At this stage, the attacker had successfully pivoted from a web-facing system into the internal network.

## Impact on Investigation Flow

Identification of `FILESERVER01.ad.compliantsecure.store` as the next target explains:
- Subsequent SMB authentication attempts using harvested credentials
- Directory enumeration of shared folders
- Later data exfiltration activity

## Next Investigative Pivot

Following host targeting and SMB discovery:
- Analyze credential access techniques used to elevate access
- Identify LSASS memory dumping activity
- Track authentication using compromised user credentials

**Next file:**  
`analysis/007-lsass-dump-and-credential-access.md`
