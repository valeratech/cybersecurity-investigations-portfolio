# Case 003 — Webshell Authentication & Command Execution

**Document Type:** Analysis  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes how the attacker authenticated to the uploaded webshell and records what the surviving notes establish about commands executed on the compromised web server. This confirms interactive control and marks the transition from exploitation to post-exploitation.

## Data Sources
- PCAP (E-001)
- Wireshark HTTP stream reconstruction
- Zeek HTTP metadata

All timestamps referenced below are treated as **UTC**.

## Webshell Access Pattern

Following the successful upload of the webshell (`mycv.aspx`), the attacker began interacting with the shell through HTTP POST requests directed at the uploaded file.

### Access Endpoint
- **URI:** `/uploads/cvs/mycv.aspx`
- **Action Parameter:** `act=cmd`
- **Method:** POST

The observed requests to this endpoint carried command input in HTTP form parameters.

## Authentication Mechanism

### Cookie-Based Authentication
Inspection of HTTP request headers revealed that the webshell enforced authentication via a hardcoded cookie value.

- **Cookie Name:** `shell_pass`
- **Cookie Value:** `<REDACTED>`

Publication note: The recovered `shell_pass` value is redacted as credential
material; the cookie name is retained for analytical context.

Example request header excerpt:
`Cookie: shell_pass=<REDACTED>; ASP.NET_SessionId=...`

The observed request included the `shell_pass` cookie with the recovered value redacted. The surviving notes contain no request without it, so whether the cookie was required is not established.

## Command Execution Interface

Commands were supplied via an HTTP POST parameter:

- **Form Parameter:** `cmd_txt`
- **Execution Context:** The webshell banner reported `SYSTEM`

The surviving request evidence records command input in the `cmd_txt` form value.

## Range-Reported and Evidenced Commands

### Range-reported first command
`ipconfig /all`

The CyberRange recorded this as the accepted answer for the first command executed through the webshell. The surviving Q5 narrative duplicates Q4 and reproduces Q4's packet; no `cmd_txt` value carrying this command appears anywhere in the notes. It is preserved here as a range assertion and is not evidenced by the surviving record.

### Earliest command with surviving command evidence
A PowerShell one-liner retrieving and invoking PowerView.ps1, recorded as a `cmd_txt` form value. Full treatment in `analysis/005-active-directory-enumeration-powershell.md`.

## Timing Evidence

- **Webshell upload:** `2025-05-20 18:28:03Z`
- **Q4 authentication request excerpt:** no timestamp preserved in the notes
- **Earliest timestamped webshell interaction:** HTTP response at `2025-05-20 18:30:27Z`

The timestamped response occurs after the recorded upload. It does not establish when the first interaction occurred, and the surviving notes support no conclusion about the pace of the attacker's workflow.

## Analytical Assessment

The use of:
- The observed `shell_pass` authentication cookie
- Direct command execution via POST parameters
- Execution of PowerShell through the `cmd_txt` parameter

Confirms that the attacker obtained **interactive remote code execution** on the HR web server.

At this point, the attacker had sufficient access to:
- Perform Active Directory enumeration
- Identify domain context
- Stage additional tooling

## Impact on Investigation Flow

Establishing authenticated webshell access explains how the attacker was able to:
- Execute PowerShell commands in memory
- Download additional scripts and binaries
- Perform Active Directory enumeration
- Dump LSASS process memory

Subsequent analysis focuses on **PowerShell-based domain enumeration activity**.

## Next Investigative Pivot

Following confirmation of command execution:
- Identify PowerShell activity executed via the webshell
- Attribute domain enumeration tooling
- Correlate traffic with LDAP-based reconnaissance

**Next file:**  
`analysis/005-active-directory-enumeration-powershell.md`
