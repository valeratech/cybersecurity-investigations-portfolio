# Final Investigation Report  
**Case ID:** 003  
**Case Title:** HR Webshell → AD Enumeration → LSASS Dump → Tunnel Pivot → SMB Exfiltration  
**Author:** Ryan Valera  
**Date Created:** 2026-01-08  
**Last Updated:** 2026-01-08  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

This investigation identified a confirmed multi-stage intrusion originating from a publicly accessible HR job application portal. The attacker exploited an unrestricted file upload vulnerability to deploy a webshell, escalated access through credential harvesting, pivoted into the internal network using a tunneling framework, and successfully exfiltrated sensitive corporate documents via SMB.

The incident represents a **full breach**, not an attempted compromise, with confirmed lateral movement and data exfiltration.

## 2. Incident Overview

### Initial Access Vector
- Entry point: `hr.compliantsecure.store`
- Vulnerability: Unrestricted file upload
- Malicious artifact: `mycv.aspx` (ASP.NET webshell)

### Attacker Objectives
- Establish persistent access
- Enumerate Active Directory
- Harvest credentials
- Pivot into internal systems
- Identify and exfiltrate sensitive data

## 3. Affected Assets

### Hosts
- **HR Web Server:** `HRWEBSERVER` (`10.10.3.115`)
- **Domain Controller:** `DC01.ad.compliantsecure.store`
- **File Server:** `FILESERVER01.ad.compliantsecure.store` (`10.10.11.216`)

### Accounts
- Compromised domain user: `michael`

## 4. Attack Timeline (UTC)

| Time | Activity |
|-----|---------|
| 18:15 | Directory enumeration against HR website |
| 18:28 | Webshell uploaded (`mycv.aspx`) |
| 18:48 | LSASS dump (`lsass.dmp`) downloaded |
| 19:07 | Tunnel established to external C2 |
| 19:14 | SMB authentication to file server |
| 19:15 | Share enumeration completed |
| 19:15+ | Document access and exfiltration |

## 5. Technical Analysis Summary

### Webshell Activity
- Authentication via hardcoded cookie value
- Command execution confirmed
- Initial recon performed using native OS commands

### Credential Access
- LSASS dumped using `rundll32.exe` with `comsvcs.dll`
- Dump extracted via HTTP
- Credentials cracked offline using standard wordlists

### Lateral Movement
- Tunnel established using Ligolo-NG
- Authenticated SMB access achieved using recovered credentials
- No brute-force or exploit-based SMB activity observed

### Data Discovery & Exfiltration
- Sensitive directories enumerated:
  - `Documents`
  - `Finance`
  - `HR`
  - `IT`
  - `Programs`
- Confirmed exfiltration of internal PDF documentation

## 6. Indicators of Compromise (IOCs)

### Network
- Attacker IP: `3.68.76.39`
- C2 IP: `52.59.195.223`
- Malicious URL: `http://52.59.195.223/agent.exe`

### Web
- Webshell: `mycv.aspx`
- Auth cookie: `shell_pass=u_h@ck3d`

### Credential Theft
- LSASS dump: `lsass.dmp`
- Dump method: `rundll32.exe` + `comsvcs.dll`

## 7. Impact Assessment

### Technical Impact
- Domain credentials compromised
- Internal network access achieved
- SMB data access without additional exploitation

### Business Impact
- Exposure of internal policy and compliance documents
- Potential exposure of HR and financial records
- Loss of confidentiality and increased regulatory risk

## 8. Root Cause Analysis

Primary contributing factors:
- Inadequate file upload validation
- Weak password hygiene
- Excessive SMB permissions
- Lack of internal network segmentation
- Insufficient monitoring of internal traffic

## 9. Recommendations

### Immediate
- Disable compromised accounts
- Rotate credentials
- Remove malicious artifacts
- Review SMB share permissions

### Short-Term
- Implement strict file upload validation
- Enforce strong password policies
- Monitor for LSASS dump activity
- Improve SMB and east-west visibility

### Long-Term
- Network segmentation
- Least-privilege access enforcement
- Behavioral monitoring for tunneling tools
- Regular adversary simulation exercises

## 10. Conclusion

This investigation confirms a **successful, end-to-end intrusion** beginning with a web application flaw and resulting in internal data exfiltration. The attacker leveraged well-known techniques executed with discipline, highlighting how a single exposed application can lead to enterprise-wide compromise when layered defenses are insufficient.

This case demonstrates the critical importance of defense-in-depth, credential hygiene, and internal monitoring.

**End of Report**
