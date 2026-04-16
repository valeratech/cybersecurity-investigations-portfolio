# Investigation Report – Case 009: OSK Hijack Persistence and Cerber Botnet Activity

**Document Type:** Investigation Summary (Root README)

**Case Title:** OSK Hijack Persistence and Cerber Botnet Activity  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Date Created:** 2026-04-16  
**Last Updated:** 2026-04-16  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## 1. Overview

### Objective
Investigate suspicious registry and process activity associated with `osk.exe` to determine whether it represents legitimate system behavior or a persistence mechanism, and analyze related endpoint and network telemetry to identify malware activity, communication patterns, and threat attribution.

### Scenario Summary
An IT technician identified a suspicious file referenced in the Windows registry during routine support. Initial investigation focused on the `osk.exe` binary, a legitimate Windows Ease of Access tool. Analysis revealed execution from a non-standard path, indicating a masquerading binary. Subsequent endpoint and network analysis confirmed persistence, large-scale outbound communication, and botnet-related activity associated with Cerber ransomware. :contentReference[oaicite:0]{index=0}

### Key Focus Areas
- Endpoint (Sysmon) Analysis  
- Network Traffic Correlation  
- Threat Intelligence Enrichment  
- Persistence Mechanism Identification  
- Malware Attribution  

## 2. Environment & Tools Used

### Environment Description
- Windows endpoint telemetry (Sysmon / Windows Event Logs)  
- SIEM platform (Splunk)  
- Network security logs (Fortigate UTM, Suricata IDS)  
- Internal host: `we8105desk[.]waynecorpinc[.]local`  
- Internal IP: `192[.]168[.]250[.]100`  

### Tools & Frameworks
- Splunk (SPL queries, log correlation)  
- Sysmon (Event ID 1, Event ID 7)  
- Fortigate UTM Logs  
- Suricata IDS  
- VirusTotal (Threat Intelligence)  
- OSINT (Microsoft documentation, malware research)  

## 3. Evidence Collected

### Evidence Artifacts
- Windows Event Logs (Sysmon – XmlWinEventLog)  
- Fortigate UTM logs  
- Suricata IDS logs  
- Threat intelligence (VirusTotal hash lookup)  

See:
- `evidence-metadata/evidence-inventory.md`

## 4. Analysis & Findings

### 4.1 Initial Indicators
- Abnormal volume of `osk.exe` activity (~49,608 events)  
- Execution from non-standard directory  
- Registry-based persistence suspicion  

### 4.2 Timeline Reconstruction
See:
- `analysis/timeline-utc.md`

### 4.3 Host-Based Analysis
- Suspicious binary execution path:
  - `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`
- Deviates from legitimate path:
  - `C:\Windows\System32\osk.exe`
- Indicates masquerading and persistence via accessibility binary hijacking  

### 4.4 Network Analysis
- Primary communication port: `6892`  
- Secondary connection: `80` (single event)  
- Unique external IPs contacted: `16,384`  
- Behavior consistent with scanning or botnet propagation  

### 4.5 Memory Analysis (if applicable)
Not applicable for this investigation.

### 4.6 Malware Behavior
- Hash identified:
  - `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B`
- VirusTotal classification: Cerber malware family  
- Fortigate classification:
  - Category: Botnet  
  - Threat: `Cerber.Botnet`  
- Suricata alert triggered:
  - `ET POLICY Possible External IP Lookup ipinfo.io`

## 5. Confirmed Findings (Executive Summary)

- Initial access vector: OSK accessibility binary hijack  
- Persistence mechanism: registry-based execution of masquerading binary  
- Malware delivery: staged executable in user AppData directory  
- C2 / botnet behavior: high-volume outbound connections over port `6892`  
- Threat attribution: Cerber ransomware family  
- Recon activity: external IP lookup via HTTP  

See:
- `analysis/findings-summary.md`
- `reports/009-osk-hijack-cerber-botnet-report.md`

## 6. Impact Assessment

- Unauthorized persistence with SYSTEM-level execution potential  
- Large-scale outbound communication indicative of botnet activity  
- Potential ransomware execution and system compromise  
- Network-wide exposure risk due to automated scanning behavior  

## 7. Indicators of Compromise (IOCs)

See:
- `iocs/network-iocs.md`

## 8. Reports

- `reports/009-osk-hijack-cerber-botnet-report.md`

## 9. Case Status

**Status:** Completed  
**Confidence Level:** High  
**Report Ready:** Yes  
