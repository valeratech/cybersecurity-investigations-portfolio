# Case 003 — LSASS Dump & Credential Access

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes the attacker’s credential access activity by identifying the method used to dump LSASS process memory, the artifacts generated, and how those artifacts enabled credential extraction. This marks a critical escalation in the attack lifecycle.

## Data Sources
- PCAP (E-001)
- Wireshark HTTP stream inspection
- Zeek HTTP metadata
- Webshell command execution records

All timestamps referenced below are treated as **UTC**.

## Credential Access Technique Overview

After identifying internal targets via SMB discovery, the attacker initiated a credential harvesting technique by dumping the Local Security Authority Subsystem Service (LSASS) process memory on the compromised web server.

LSASS stores sensitive authentication material, including:
- NTLM password hashes
- Kerberos tickets
- Cached credentials
- DPAPI master keys

Dumping LSASS provides attackers with offline access to these secrets.

## LSASS Dump Execution Method

### Observed Command Pattern
The following command was executed through the webshell interface via an HTTP POST request:
```
powershell -exec Bypass -c "C:\Windows\System32\rundll32.exe
C:\Windows\System32\comsvcs.dll, MiniDump
(Get-Process lsass).Id
$env:TEMP\lsass.dmp full"
```

### Key Components
- **Executable:** `rundll32.exe`
- **DLL Used:** `comsvcs.dll`
- **Function:** `MiniDump`
- **Target Process:** `lsass.exe`
- **Output File:** `lsass.dmp`

This technique leverages a legitimate Windows DLL to perform a memory dump, reducing reliance on third-party tooling and increasing stealth.

## Network Evidence of Dump Activity

Wireshark inspection of HTTP POST parameters revealed:
- The full PowerShell command embedded in the request body
- Execution occurring via the webshell endpoint
- No evidence of upload blocking or execution failure

This confirms the dump was initiated successfully on the host.

## Dump File Handling

Following dump creation:
- The file `lsass.dmp` was written to the Windows temporary directory
- The attacker later accessed the webshell’s file browser functionality to retrieve the dump file

This behavior indicates intent to perform **offline credential extraction** rather than live credential abuse.

## Analytical Assessment

The use of:
- A built-in Windows binary (`rundll32.exe`)
- A native DLL (`comsvcs.dll`)
- In-memory PowerShell execution

Demonstrates a **living-off-the-land** approach to credential access. This technique is commonly used to evade endpoint detection and minimize forensic footprint.

At this point in the attack:
- The attacker no longer relied solely on webshell access
- Credential material was harvested for broader network access

## Impact on Investigation Flow

Successful LSASS dumping explains:
- Subsequent authenticated SMB access using domain user credentials
- The attacker’s ability to pivot further into the internal network
- Later data exfiltration activity over an established tunnel

## Next Investigative Pivot

Following confirmation of LSASS dump creation:
- Identify the timestamp of dump file retrieval
- Analyze offline credential extraction workflow
- Attribute cracked credentials to subsequent authentication events

**Next file:**  
`analysis/008-lsass-dump-retrieval-and-offline-credential-extraction.md`
