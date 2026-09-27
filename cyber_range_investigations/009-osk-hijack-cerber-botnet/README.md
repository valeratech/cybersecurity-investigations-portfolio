# Investigation Report – Case 009: OSK Hijack Persistence and Cerber Botnet Activity

**Document Type:** Case Overview  
**Case Title:** OSK Hijack Persistence and Cerber Botnet Activity  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Documentation Started:** 2026-04-16  
**Documentation Last Updated:** 2026-09-26  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Case Contents

### Analysis

- [Findings Summary](analysis/findings-summary.md)
- [Host Analysis](analysis/host-analysis.md)
- [Initial Indicators](analysis/initial-indicators.md)
- [Malware Behavior](analysis/malware-behavior.md)
- [Network Analysis](analysis/network-analysis.md)
- [Timeline](analysis/timeline-utc.md)

### Case Notes

- [Analysis Tools and Methods](case-notes/analysis-tools-and-methods.md)
- [Investigation Procedure and Findings](case-notes/investigation-procedure-and-findings.md)

### Evidence Metadata

- [Evidence Inventory](evidence-metadata/evidence-inventory.md)
- [Tools Usage Documentation](evidence-metadata/tools-usage-documentation.md)

### Indicators of Compromise

- [Network IOCs](iocs/network-iocs.md)

### Reports

- [Final Report](reports/final-report.md)

### Supporting Directories

Directory notes: [scripts](scripts/README.md), [pcaps](pcaps/README.md), [screenshots](screenshots/README.md).

## 1. Overview

### Objective

Determine whether the `osk.exe` entry reported by an IT technician is legitimate or malicious and what it is doing, using Splunk searches of Windows event, Fortigate UTM and Suricata logs, together with VirusTotal and OSINT.

### Scenario Summary

**Range-supplied.** The range titles this lab "Cerber Ransomware Persistence via OSK Hijack". Its scenario reports an unexpected file in the registry of an employee's system, and asks whether the file is legitimate or malicious and what it is doing.
The thirteen questions lead from OSINT on `osk.exe` to the endpoint's Windows event logs, to VirusTotal, and to Fortigate UTM and Suricata logs.

### Key Focus Areas

- Execution path and masquerading of `osk.exe`
- Host context and event volume
- Destination ports and distinct destinations
- Hash identification and malware family
- Firewall and IDS enrichment

## 2. Environment & Tools Used

### Environment Description

- Splunk with the `botsv1` dataset, on the SIEM machine in the range
- Windows event logs in XML (Sysmon telemetry), Fortigate UTM logs and Suricata logs
- Endpoint `we8105desk[.]waynecorpinc[.]local`, internal address `192[.]168[.]250[.]100`, user `bob.smith` (Q5)

### Tools & Frameworks

- Splunk search (SPL)
- VirusTotal
- OSINT, including Microsoft documentation

## 3. Evidence Basis

The case rests on the analyst's notes for the thirteen questions. For each question they record the question text, the recorded answer, the analyst's notes, and the SPL queries and field statistics where used, together with two screenshots of Splunk field summaries.

The data sources those searches reference, the Investigation Scope statement and the handling limitations are recorded in the [Evidence Inventory](evidence-metadata/evidence-inventory.md).

## 4. Analysis & Findings

### 4.1 Purpose and Expected Path of `osk.exe` (Q1, Q2)

**Range-accepted.** Accessibility On-Screen Keyboard (Q1); expected location `C:\Windows\System32` (Q2).

**External enrichment.** Microsoft documentation and OSINT in the notes describe a built-in virtual keyboard that can be launched at the Windows logon screen with elevated privileges.

### 4.2 Event Volume (Q3)

**Range-accepted.** 49,608 events contain `osk.exe`.

### 4.3 Execution Path (Q4)

**Range-accepted.** `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`.

**Observed.** The `Image` field summary shows it in 49,594 events (99.972%).

**Analyst inference.** The notes read the location outside `C:\Windows\System32` as a masquerading executable.

### 4.4 Host, Address and User (Q5)

**Range-accepted.** `we8105desk[.]waynecorpinc[.]local`; `192[.]168[.]250[.]100`; `bob.smith`.

### 4.5 Destination Ports (Q6)

**Observed.** 6892 in 48,196 events (99.998%) and 80 in 1 event (0.002%), among events carrying `DestinationPort` (97.156%).

### 4.6 Distinct Destinations on Port 6892 (Q7)

**Range-accepted.** 16,384 distinct destination addresses of connection attempts on port 6892.

**Analyst inference.** The notes read this as consistent with automated scanning or botnet-like behaviour.

### 4.7 SHA-256 and Malware Family (Q8, Q9, Q12)

**Range-accepted.** `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B` (Q8); Cerber (Q9, from VirusTotal); Ransomware (Q12, from OSINT).

### 4.8 Fortigate UTM Classification (Q10, Q11)

**Range-accepted.** `appcat` Botnet (Q10) and `app` Cerber.Botnet (Q11) for traffic to destination port 6892; both are Fortigate enrichment labels.
They do not establish communication with botnet infrastructure.

### 4.9 Port-80 Connection and Suricata Alert (Q13)

**Observed.** Destination `54[.]148[.]194[.]58` for the single port-80 event.

**Range-accepted.** Suricata signature `ET POLICY Possible External IP Lookup ipinfo.io`; the analyst's notes give `ET INFO External IP Lookup`. The values differ and are not reconciled.

## 5. Summary of Findings

See:
- [Findings Summary](analysis/findings-summary.md)
- [Final Report](reports/final-report.md)

## 6. Limitations

- No time in the record carries a timezone designation, and none is converted. The one recorded case-event time is in the Q10 notes; see the [Timeline](analysis/timeline-utc.md).
- Persistence is range-supplied framing from the lab title and Q1; no registry query, result or persistence mechanism is recorded.
- Firewall categories, the Suricata signature and VirusTotal detections are enrichment. They do not establish the behaviours they name.
- The Q13 signature has two recorded values, which are preserved with their sources.
- Collection dates for the searches and screenshots are not recorded.
- Matters outside the question set were not examined and are not open items.

## 7. Indicators of Compromise (IOCs)

See:
- [Network IOCs](iocs/network-iocs.md)

## 8. Reports

- [Final Report](reports/final-report.md)

## 9. Case Status

**Status:** Complete  
