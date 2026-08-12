# Final Investigation Report  
**Document Type:** Final Report  
**Case Title:** HR Webshell → AD Enum → LSASS Dump → Tunnel Pivot → SMB Enumeration  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Documentation Started:** 2026-01-08  
**Documentation Last Updated:** 2026-01-18  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Executive Summary

This investigation identified a confirmed multi-stage intrusion originating from a publicly accessible HR job application portal. The attacker exploited an unrestricted file upload vulnerability to deploy a webshell, escalated access through credential harvesting, pivoted into the internal network after initiating tunnel-related connectivity, and enumerated sensitive corporate document names via SMB.

The incident represents a **confirmed intrusion** with authenticated SMB access to an internal file share and enumeration of directories and filenames. No SMB read or file-transfer activity is recorded in the surviving evidence.

## 2. Incident Overview

### Initial Access Vector
- Entry point: `hr[.]compliantsecure[.]store`
- Vulnerability: Unrestricted file upload
- Malicious artifact: `mycv.aspx` (ASP.NET webshell)

### Attacker Objectives
- Enumerate Active Directory
- Harvest credentials
- Pivot into internal systems
- Identify sensitive data

## 3. Affected Assets

### Hosts
- **HR Web Server:** `HRWEBSERVER` (`10[.]10[.]3[.]115`)
- **File Server:** `FILESERVER01[.]ad[.]compliantsecure[.]store` (`10[.]10[.]11[.]216`)

### Accounts
- Compromised domain user: `michael`

## 4. Attack Timeline (UTC)

| Time | Activity |
|-----|---------|
| 18:15 | Directory enumeration against HR website |
| 18:28 | Webshell uploaded (`mycv.aspx`) |
| 18:48 | LSASS dump (`lsass.dmp`) downloaded |
| 19:07:43 | Tunnel-related connection initiated to remote host |
| 19:14 | SMB authentication to file server |
| 19:15 | Share enumeration completed |

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
- Tunnel-related connection initiated to the remote host; payload identified as Ligolo-NG via VirusTotal enrichment
- Authenticated SMB access achieved using recovered credentials
- No brute-force or exploit-based SMB activity observed

### Data Discovery
- Sensitive directories enumerated:
  - `Documents`
  - `Finance`
  - `HR`
  - `IT`
  - `Programs`
- Internal PDF and Office document names observed in the share listing

## 6. Indicators of Compromise (IOCs)

### Network
- Attacker IP: `3[.]68[.]76[.]39`
- Remote host: `52[.]59[.]195[.]223`
- Malicious URL: `hxxp://52[.]59[.]195[.]223/agent.exe`

### Web
- Webshell: `mycv.aspx`
- Auth cookie: `shell_pass=<REDACTED>`

### Credential Theft
- LSASS dump: `lsass.dmp`
- Dump method: `rundll32.exe` + `comsvcs.dll`

## 7. Impact Assessment

### Technical Impact
- Domain credentials compromised
- Internal network access achieved
- Authenticated SMB access to `FILESERVER01` and directory-name enumeration using recovered credentials

### Business Impact
- Internal policy and compliance document names were returned in the SMB directory listing
- The surviving evidence records directory and file-name disclosure, not file-content access or transfer

## 8. Contributing Factors Supported by the Record

- The upload path accepted the ASPX webshell
- Michael's credential was recovered through the recorded dictionary-cracking workflow in under a minute

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

This investigation confirms an intrusion beginning with a web application flaw and reaching authenticated access to internal file shares. The intrusion progressed from compromise of the exposed web application to authenticated access to an internal file share using recovered credentials.

This case demonstrates the critical importance of defense-in-depth, credential hygiene, and internal monitoring.

## Related Documents

- [Case Overview](../README.md)
- [Evidence Register](../evidence-metadata/evidence-register.md)

**End of Report**
