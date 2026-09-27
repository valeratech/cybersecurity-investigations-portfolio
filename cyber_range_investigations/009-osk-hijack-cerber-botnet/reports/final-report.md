# Final Report – OSK Hijack Persistence and Cerber Botnet Activity

**Document Type:** Final Report  
**Case Title:** OSK Hijack Persistence and Cerber Botnet Activity  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Documentation Started:** 2026-04-16  
**Documentation Last Updated:** 2026-09-26  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## 1. Executive Summary

The range titles this lab "Cerber Ransomware Persistence via OSK Hijack", and its scenario reports an unexpected file in the registry of an employee's system.

Across thirteen questions, the record identifies a binary named `osk.exe` running on `we8105desk[.]waynecorpinc[.]local` from `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe`, outside the expected `C:\Windows\System32`.
VirusTotal associates its SHA-256 with the Cerber family, which OSINT describes as ransomware.
Its events show connection attempts to destination port 6892 across 16,384 distinct destination addresses, traffic that Fortigate UTM classifies as Botnet and Cerber.Botnet, and a single port-80 connection for which a Suricata alert fired.

The record does not establish persistence, a registry mechanism, how the binary arrived, encryption or other impact, or any order among these events.

## 2. Scope and Evidence Reviewed

### Scope

The investigation was a structured CyberRange question set of thirteen questions. Its Investigation Scope statement is recorded in the [Evidence Inventory](../evidence-metadata/evidence-inventory.md).

### Evidence Reviewed

- Analyst notes for the thirteen questions, with the recorded answers, SPL queries and field statistics (EV-001).
- Two screenshots of Splunk field summaries: `Image` (Q4) and `DestinationPort` (Q6) (EV-002).
- Data sources referenced: Windows event logs in XML (Sysmon telemetry), Fortigate UTM logs, Suricata logs, VirusTotal and OSINT.

## 3. Time Basis

- **Display time and device time, no timezone designation:** the Fortigate event in the Q10 notes, displayed as `8/24/164:49:41.000 PM` and written in the log text as `Aug 24 10:49:41` and `date=2016-08-24 time=10:49:40`.
- **Relative display age, not an event time:** `9 months ago` on two VirusTotal community entries in the Q9 notes.
- **No recorded time:** all other values, including the counts in Q3, Q4, Q6 and Q7.

No value carries a UTC designation, and none is converted. Values from different sources are not ordered against each other.

See:
- [Timeline](../analysis/timeline-utc.md)

## 4. Findings

### 4.1 Masquerading Binary

**Range-accepted.** `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe` (Q4), outside `C:\Windows\System32` (Q2).

**Observed.** The suspicious path appears in 49,594 events in the `Image` field summary.

**Analyst inference.** The notes read the name-location mismatch as a masquerading executable.

### 4.2 Host Context and Event Volume

**Range-accepted.** Host `we8105desk[.]waynecorpinc[.]local`, internal address `192[.]168[.]250[.]100`, user `bob.smith` (Q5); 49,608 events containing `osk.exe` (Q3).

### 4.3 Network Activity

**Observed.** Destination port 6892 in 48,196 events (99.998%) and port 80 in 1 event (0.002%), among events carrying `DestinationPort` (97.156%) (Q6).

**Range-accepted.** 16,384 distinct destination addresses of connection attempts on port 6892 (Q7).

**Analyst inference.** The notes read this as consistent with custom-service or command-and-control communication, automated scanning, or botnet-like behaviour.

### 4.4 Hash and Malware Family

**Range-accepted.** SHA-256 `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B` (Q8); family Cerber (Q9); primary function Ransomware (Q12).

**External enrichment.** VirusTotal detections supply the family; OSINT describes Cerber as ransomware that encrypts files and demands payment.
No such effect is recorded in this case.

### 4.5 Firewall Classification

**Range-accepted.** Fortigate UTM assigns `appcat` Botnet (Q10) and `app` Cerber.Botnet (Q11) to traffic to destination port 6892.

**Observed.** The one reproduced Fortigate event shows protocol 17 (`udp/6892`), action pass and application list Honeypot-Access.
These labels do not establish communication with botnet infrastructure.

### 4.6 Port-80 Connection and Suricata Alert

**Observed.** Destination `54[.]148[.]194[.]58` for the single port-80 event (Q13 notes).

**Range-accepted.** Suricata signature `ET POLICY Possible External IP Lookup ipinfo.io`; the analyst's notes give `ET INFO External IP Lookup`. The two values differ and are not reconciled.

**Analyst inference.** The notes read the alert as an external IP lookup associated with reconnaissance.

## 5. Indicators of Compromise

See:
- [Network IOCs](../iocs/network-iocs.md)

## 6. Conclusion

**Analyst inference.** The record supports a masquerading binary named `osk.exe` running from a user-profile folder on `we8105desk[.]waynecorpinc[.]local`, identified through its hash with the Cerber family, and associated by Fortigate enrichment with Cerber.Botnet traffic on port 6892.
The lab's persistence framing is not observed in the record.

## 7. Recommendations

- Alert on Windows system binary names executing from user-profile directories.
- Monitor accessibility-tool execution, including at the logon screen.
- Review outbound traffic to non-standard ports such as 6892, and high distinct-destination counts.
- Use the SHA-256 and the full file path from the IOC collection for detection and threat hunting.

## 8. Limitations

- No time in the record carries a timezone designation, and none is converted. Values from different sources are not ordered against each other.
- The Q10 event is the only recorded case-event timestamp; the Q9 relative ages are external enrichment display ages.
- Persistence is range-supplied framing; no registry query, result or persistence mechanism is recorded.
- Detection and classification labels from Fortigate UTM, Suricata and VirusTotal are enrichment, and do not establish the behaviours they name.
- The Q13 signature has two recorded values, `ET POLICY Possible External IP Lookup ipinfo.io` and `ET INFO External IP Lookup`, preserved with their sources.
- The Q8 search matches both the legitimate and the suspicious path; the hash is the range-accepted answer.
- The `Image` field summary shows further values whose matching field and command lines are not recorded; no action is attributed to them.
- Collection dates for the searches and screenshots are not recorded.
- Matters outside the question set were not examined and are not open items.

## Related Documents

- [Case Overview](../README.md)
- [Timeline](../analysis/timeline-utc.md)
- [Indicators of Compromise](../iocs/network-iocs.md)
- [Evidence Inventory](../evidence-metadata/evidence-inventory.md)
