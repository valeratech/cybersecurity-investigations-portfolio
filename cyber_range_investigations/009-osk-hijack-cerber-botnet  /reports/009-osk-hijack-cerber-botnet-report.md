# Investigation Report – OSK Hijack Persistence and Cerber Botnet Activity

**Document Type:** Report

**Case Title:** OSK Hijack Persistence and Cerber Botnet Activity  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Date Created:** 2026-04-16  
**Last Updated:** 2026-04-16  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## 1. Executive Summary

This investigation identified a compromised Windows endpoint leveraging a hijacked `osk.exe` (On-Screen Keyboard) binary to establish persistence. The malicious binary was executed from a user-controlled directory, deviating from the legitimate system path. 

Endpoint and network telemetry analysis revealed high-volume outbound communication over a non-standard port, indicative of botnet behavior. Threat intelligence correlation confirmed the malware as part of the Cerber ransomware family, specifically associated with botnet activity.

The compromised system demonstrates characteristics of persistence, command-and-control communication, reconnaissance behavior, and potential ransomware execution.

## 2. Scope and Objectives

### Objective
- Identify the nature of the suspicious `osk.exe` activity  
- Determine whether the binary is legitimate or malicious  
- Analyze host and network behavior  
- Attribute the malware using threat intelligence  
- Assess impact and provide remediation guidance  

### Scope
- Endpoint telemetry (Sysmon logs)  
- Network security logs (Fortigate UTM, Suricata IDS)  
- Threat intelligence enrichment (VirusTotal)  

## 3. Key Findings

- Masquerading binary executed from:
  - `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`
- Legitimate path:
  - `C:\Windows\System32\osk.exe`
- Compromised host:
  - `we8105desk[.]waynecorpinc[.]local`
  - `192[.]168[.]250[.]100`
- Abnormal process activity:
  - ~49,608 events
- Network behavior:
  - Primary port: `6892`
  - Secondary port: `80`
  - Unique external IPs: `16,384`
- Malware identification:
  - SHA256: `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`
  - Family: Cerber
- Network classification:
  - Category: Botnet
  - Threat: `Cerber.Botnet`
- Reconnaissance activity:
  - External IP lookup via `ipinfo[.]io`

## 4. Attack Chain Summary

1. **Persistence Established**
   - OSK binary hijack using a masquerading executable  

2. **Execution**
   - Malicious `osk.exe` executed from AppData directory  

3. **Command-and-Control Communication**
   - High-volume outbound traffic over port `6892`  

4. **Reconnaissance**
   - External IP lookup via HTTP (port `80`)  

5. **Malware Attribution**
   - Hash-based identification confirms Cerber ransomware  

## 5. Impact Assessment

- Unauthorized persistence with potential SYSTEM-level execution  
- Active communication with botnet infrastructure  
- Potential ransomware execution and file encryption  
- High-risk exposure due to large-scale outbound communication  
- Possible lateral movement or further compromise within network  

## 6. Indicators of Compromise

See:
- `../iocs/network-iocs.md`

## 7. Recommendations

- Block outbound traffic on non-essential ports, including `6892`  
- Monitor and alert on execution of system binaries from non-standard paths  
- Enforce application control and binary path validation  
- Restrict or monitor accessibility tool execution at login screen  
- Implement endpoint detection rules for OSK hijacking behavior  
- Monitor for abnormal outbound connection volumes  
- Leverage threat intelligence feeds for Cerber indicators  

## 8. Conclusion

The investigation confirms a high-confidence compromise involving Cerber malware leveraging OSK hijacking for persistence. The infected system is actively participating in botnet-related activity and exhibits behavior consistent with ransomware operations. Immediate containment and remediation actions are required to mitigate further risk.
