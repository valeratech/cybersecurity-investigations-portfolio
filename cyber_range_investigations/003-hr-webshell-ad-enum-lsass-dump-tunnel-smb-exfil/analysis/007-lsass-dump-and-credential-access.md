# Case 003 — LSASS Dump & Credential Access

**Document Type:** Analysis  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes the attacker's credential access activity by identifying the method used to dump LSASS process memory, the artifacts generated, and how those artifacts enabled credential extraction. This marks a critical escalation in the attack lifecycle.

## Data Sources
- PCAP (E-001)
- Wireshark HTTP stream inspection
- Zeek HTTP metadata
- Webshell command execution records

All timestamps referenced below are treated as **UTC**.

## Credential Access Technique Overview

The attacker dumped the Local Security Authority Subsystem Service (LSASS) process memory on the compromised web server.

**Range-provided context:** LSASS stores sensitive authentication material, including:
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

## Network Evidence of Dump Activity

Wireshark inspection of HTTP POST parameters revealed:
- The full PowerShell command embedded in the request body
- Execution occurring via the webshell endpoint

The later HTTP response for `lsass.dmp` records `Content-Length: 41377812`, establishing that the dump file was produced.

## Dump File Handling

Following dump creation:
- The file `lsass.dmp` was written to the Windows temporary directory
- The attacker later accessed the webshell's file browser functionality to retrieve the dump file

The observed command creates an LSASS memory dump; the surviving record does not establish the attacker's intended post-dump use.

## Analytical Assessment

**Analyst interpretation:** the observed command invokes `rundll32.exe` and `comsvcs.dll` through PowerShell, which is consistent with a **living-off-the-land** approach to credential access.

## Impact on Investigation Flow

Successful LSASS dumping explains:
- Subsequent authenticated SMB access using domain user credentials
- Later SMB share enumeration activity

## Next Investigative Pivot

Following confirmation of LSASS dump creation:
- Identify the timestamp of dump file retrieval
- Analyze offline credential extraction workflow
- Attribute cracked credentials to subsequent authentication events

**Next file:**  
`analysis/008-lsass-dump-retrieval-and-offline-credential-extraction.md`
