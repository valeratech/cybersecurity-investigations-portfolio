# Tools Usage Documentation

**Document Type:** Reference  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Purpose

This document records how each tool and data source was used in the recorded question set. The queries are reproduced exactly as recorded in [Analysis Tools and Methods](../case-notes/analysis-tools-and-methods.md).

## Platform Usage

### Splunk

- The lab instructions direct every search to the `botsv1` dataset, with event sampling off and the time range set to All Time.
- Searches of the Windows event logs for events containing `osk.exe` supplied the event count (Q3), the `Image` path (Q4), the host, address and user values (Q5), the destination ports (Q6) and the distinct destination count on port 6892 (Q7).
- A search of Image Loaded events (`EventCode=7`) for `*osk.exe*` supplied the `Hashes` field value from which the SHA-256 was extracted (Q8).
- A Fortigate UTM search on destination port 6892 supplied the `appcat` and `app` values (Q10, Q11).
- A Suricata search on the port-80 destination address supplied the alert signature (Q13).
- The `Image` and `DestinationPort` field summaries were viewed and captured in two screenshots (Q4, Q6).

### VirusTotal

- The SHA-256 from Q8 was submitted, and the Detection and Community pages were reviewed for the malware family (Q9).
- The recorded answer is `Cerber`. The notes quote community entries that link to further vendor reports.

### OSINT

- Microsoft documentation was consulted for the purpose of `osk.exe`; the recorded answer is Accessibility On-Screen Keyboard (Q1).
- An OSINT search gave the expected location of the legitimate binary; the recorded answer is `C:\Windows\System32` (Q2).
- An OSINT search on Cerber gave its primary function; the recorded answer is Ransomware (Q12).

## Notes

- Field names differ between sources: the Sysmon field `DestinationIp` corresponds to the Suricata field `dest_ip` (Q13).
- Collection dates for the searches are not recorded.
