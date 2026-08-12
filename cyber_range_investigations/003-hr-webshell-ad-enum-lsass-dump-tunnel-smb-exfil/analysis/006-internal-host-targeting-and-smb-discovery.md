# Case 003 — Internal Host Targeting & SMB Discovery

**Document Type:** Analysis  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
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

Network traffic following the PowerShell enumeration revealed SMB communication initiated from the compromised web server toward an internal file server. How the attacker selected this host is not recorded — see the unrecoverable commands noted in `analysis/005-active-directory-enumeration-powershell.md`.

## Target Host Identified

SMB session setup and tree connect requests revealed the following target:

- **Hostname:** `FILESERVER01[.]ad[.]compliantsecure[.]store`
- **IP Address:** `10[.]10[.]11[.]216`
- **Service:** SMB over TCP/445

The surviving notes record SMB activity directed at this host; they do not record why it was selected.

## SMB Discovery Evidence

### Initial SMB Session Setup
Wireshark analysis revealed SMB2 Session Setup requests originating from the compromised host:

- **Source:** `10[.]10[.]3[.]115` (HRWEBSERVER)
- **Destination:** `10[.]10[.]11[.]216` (FILESERVER01)
- **Protocol:** SMB2
- **Authentication Context:** Domain machine account (`HRWEBSERVER$`)

The compromised HR web server authenticated to `FILESERVER01` over SMB using its machine account, `HRWEBSERVER$`. This occurred before Michael's recovered credentials were later used for SMB authentication.

## Share Enumeration Activity

Subsequent SMB2 traffic included Tree Connect requests targeting administrative and IPC shares:

`\\FILESERVER01[.]ad[.]compliantsecure[.]store\IPC$`

This is a common initial step to:
- Validate connectivity
- Enumerate available shares
- Prepare for directory listing operations

## Zeek Correlation

Zeek SMB mapping logs corroborated packet-level findings:

- **Mapped Path:** `\\FILESERVER01[.]ad[.]compliantsecure[.]store\IPC$`
- **Timestamp:** `2025-05-20 18:45:29.586745Z`
- **Initiator:** `10[.]10[.]3[.]115`

## Analytical Assessment

The observed behavior demonstrates:
- A logical progression from AD enumeration to host targeting
- Use of SMB discovery techniques to enumerate accessible resources

At `2025-05-20 18:45:29.586745Z`, the compromised web server authenticated to `FILESERVER01` over SMB using `HRWEBSERVER$`. This demonstrates internal network reach from the compromised host; it does not evidence use of the tunnel-related connection initiated at 19:07:43Z.

## Impact on Investigation Flow

Identification of `FILESERVER01[.]ad[.]compliantsecure[.]store` as the next target explains:
- Subsequent SMB authentication attempts using harvested credentials
- Directory enumeration of shared folders
- Later SMB share enumeration activity

## Next Investigative Pivot

Following host targeting and SMB discovery:
- Analyze credential access techniques used to elevate access
- Identify LSASS memory dumping activity
- Track authentication using compromised user credentials

**Next file:**  
`analysis/007-lsass-dump-and-credential-access.md`
