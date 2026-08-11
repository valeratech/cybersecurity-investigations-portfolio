# Case 003 — Impact Assessment & Investigation Summary

**Document Type:** Findings Summary  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document provides a consolidated assessment of the intrusion, including the scope of compromise, confirmed attacker actions, exposed assets, and overall business and security impact. It summarizes the investigation from initial access through SMB share enumeration.

## Executive Summary

The investigation confirmed a multi-stage intrusion beginning with exploitation of a web application vulnerability and culminating in authenticated access to an internal file share and enumeration of its directories and filenames. The attacker demonstrated deliberate tradecraft, progressing from web compromise to credential harvesting, lateral movement, and filename discovery.

This was a **confirmed breach**, not an attempted intrusion.

## Confirmed Findings and Attack Chain Overview

### 1. Initial Access
- Entry point: HR job application portal (`hr[.]compliantsecure[.]store`)
- Vulnerability exploited: Unrestricted file upload
- Result: Webshell (`mycv.aspx`) deployed on HR web server

### 2. Reconnaissance and Post-Exploitation
- Network scanning observed using `nmap` at 18:20:46Z, preceding the webshell upload at 18:28:03Z
- Webshell used for host reconnaissance
- Internal system information gathered via command execution

### 3. Credential Access
- LSASS memory dumped using `rundll32.exe` and `comsvcs.dll`
- Dump retrieved through webshell file browser
- Offline credential extraction performed
- Weak domain password successfully cracked

### 4. Lateral Movement
- Tunnel-related connection initiated to the remote host
- Authenticated SMB access achieved using cracked credentials
- Internal file server accessed without additional exploitation

`52[.]59[.]195[.]223` served `agent.exe`. VirusTotal enrichment identified the payload as Ligolo-NG. At 19:07:43 UTC, the compromised host sent a TCP SYN to the same remote host on port 11601, evidencing initiation of a connection associated with the suspected tunnel activity.

### 5. Discovery
- Sensitive directories enumerated
- Business documents identified
- Names of confidential PDF files observed in the share listing

## Scope of Compromise

### Systems Affected
- HR Web Server (`HRWEBSERVER`)
- Active Directory credentials (user account: michael)
- Internal File Server (`FILESERVER01`)

### Data Exposed
- Corporate policy documentation
- Potential access to HR and Finance records
- No file read or transfer volume is recorded in the surviving evidence

## Security Impact Assessment

### Technical Impact
- Credential theft enabled full domain-authenticated access
- SMB shares lacked least-privilege enforcement

### Business Impact
- Exposure of internal corporate documentation
- Potential regulatory exposure (HR/Finance data)
- Loss of confidentiality and trust

## Defensive Gaps Identified

- Inadequate file upload validation on public web application
- Excessive SMB permissions granted to standard domain users
- Weak password hygiene enabling offline cracking
- Lack of east-west network segmentation
- Insufficient monitoring of internal SMB and tunnel traffic

## Lessons Learned

- Web application compromise can quickly escalate to full domain breach
- LSASS dumping remains a highly effective credential theft method
- Tunnel-based pivoting enables stealthy lateral movement
- Preventative controls are far more effective than detection alone

## Investigation Conclusion

This investigation confirms an intrusion reaching authenticated enumeration of an internal file share. The attacker demonstrated methodical execution, leveraging common but effective techniques at each stage of the kill chain. Defensive failures at multiple layers enabled escalation from a single web vulnerability to internal file share access.

**Next file:**  
`reports/final-report.md`
