# Case 003 — Webshell Authentication & Command Execution

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document analyzes how the attacker authenticated to the uploaded webshell and documents the initial commands executed on the compromised web server. This confirms interactive control and marks the transition from exploitation to post-exploitation.

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

This endpoint provided interactive command execution functionality through HTTP form parameters.

## Authentication Mechanism

### Cookie-Based Authentication
Inspection of HTTP request headers revealed that the webshell enforced authentication via a hardcoded cookie value.

- **Cookie Name:** `shell_pass`
- **Cookie Value:** `u_h@ck3d`

Example request header excerpt:
`Cookie: shell_pass=u_h@ck3d; ASP.NET_SessionId=...`

The presence of this cookie was required to successfully execute commands through the webshell interface.

## Command Execution Interface

Commands were supplied via an HTTP POST parameter:

- **Form Parameter:** `cmd_txt`
- **Execution Context:** Server-side command execution under IIS worker process

This confirms the webshell provided direct command execution capability without additional server-side authentication controls.

## First Observed Command Executed

### Command
`ipconfig /all`

### Purpose
This command was used to:
- Enumerate network interfaces
- Identify IP configuration
- Determine domain membership and internal network visibility

This is a common first-stage reconnaissance command following initial access.

## Timing Evidence

- **Webshell interaction timestamp:** Shortly after upload at `2025-05-20 18:28Z`
- **Command execution confirmed:** Immediately following authentication

This rapid progression indicates:
- Automated or well-rehearsed attacker workflow
- No trial-and-error interaction
- Prior familiarity with the webshell functionality

## Analytical Assessment

The use of:
- A static authentication cookie
- Direct command execution via POST parameters
- Immediate execution of system reconnaissance commands

Confirms that the attacker obtained **interactive remote code execution** on the HR web server.

At this point, the attacker had sufficient access to:
- Enumerate the local system
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
