# Case 003 — Impact Assessment & Investigation Summary

**Case ID:** 003  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose
This document provides a consolidated assessment of the intrusion, including the scope of compromise, confirmed attacker actions, exposed assets, and overall business and security impact. It summarizes the investigation from initial access through data exfiltration.

## Executive Summary

The investigation confirmed a multi-stage intrusion beginning with exploitation of a web application vulnerability and culminating in successful internal data exfiltration. The attacker demonstrated deliberate tradecraft, progressing from web compromise to credential harvesting, lateral movement, and targeted document theft.

This was a **confirmed breach**, not an attempted intrusion.

## Attack Chain Overview

### 1. Initial Access
- Entry point: HR job application portal (`hr.compliantsecure.store`)
- Vulnerability exploited: Unrestricted file upload
- Result: Webshell (`mycv.aspx`) deployed on HR web server

### 2. Post-Exploitation & Reconnaissance
- Webshell used for host reconnaissance
- Network scanning observed using `nmap`
- Internal system information gathered via command execution

### 3. Credential Access
- LSASS memory dumped using `rundll32.exe` and `comsvcs.dll`
- Dump retrieved through webshell file browser
- Offline credential extraction performed
- Weak domain password successfully cracked

### 4. Lateral Movement
- Tunnel established using Ligolo-NG
- Authenticated SMB access achieved using cracked credentials
- Internal file server accessed without additional exploitation

### 5. Discovery & Exfiltration
- Sensitive directories enumerated
- Business documents identified
- Confirmed exfiltration of confidential PDF files

## Scope of Compromise

### Systems Affected
- HR Web Server (`HRWEBSERVER`)
- Active Directory credentials (user account: michael)
- Internal File Server (`FILESERVER01`)

### Data Exposed
- Corporate policy documentation
- Potential access to HR and Finance records
- Unknown total volume of exfiltrated data

## Security Impact Assessment

### Technical Impact
- Credential theft enabled full domain-authenticated access
- Tunnel bypassed perimeter defenses
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

This investigation confirms a **successful intrusion with data exfiltration**. The attacker demonstrated methodical execution, leveraging common but effective techniques at each stage of the kill chain. Defensive failures at multiple layers enabled escalation from a single web vulnerability to internal data theft.

## Next Steps

- Produce final investigation report
- Map attacker actions to MITRE ATT&CK
- Document remediation recommendations
- Archive investigation artifacts

**Next file:**  
`reports/003-final-investigation-report.md`
