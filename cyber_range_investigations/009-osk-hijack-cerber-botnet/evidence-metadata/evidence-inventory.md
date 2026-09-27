# Evidence Inventory – OSK Hijack Persistence and Cerber Botnet Activity

**Document Type:** Evidence Inventory  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Investigation Scope

This investigation was conducted as a structured CyberRange question set using the artifacts available within the range. The investigation concluded when the final question was answered. Evidence or analysis outside the scope of those questions was not collected and is not treated as missing or pending investigative work.

## Evidence Register

| Evidence ID | Description | Form | Contents |
|---|---|---|---|
| EV-001 | Analyst notes for the thirteen-question set | Document | Lab title and scenario; for each question: question text, recorded answer, analyst notes, and the SPL queries and field statistics where used |
| EV-002 | Screenshots of Splunk field summaries | Images embedded in EV-001 | 2 screenshots: the `Image` field summary (Q4) and the `DestinationPort` field summary (Q6) |

## Data Sources Shown in the Record

These are the data sources that the searches and views in EV-001 and EV-002 reference. They are listed as sources, not as retained evidence; exports of them are not part of the case record.

| Source ID | Source | Fields or values | Questions |
|---|---|---|---|
| DS-001 | Windows event logs in XML (Sysmon telemetry) | `XmlWinEventLog`; `Image`, `Computer`, `SourceIp`, `User`, `DestinationIp`, `DestinationPort`, `EventCode`, `ImageLoaded`, `Hashes` | Q3 to Q8, Q13 |
| DS-002 | Fortigate UTM logs | `fortigate_utm`; `dest_port`, `appcat`, `app`, `msg` | Q10, Q11 |
| DS-003 | Suricata logs | `suricata`; `dest_ip`, `dest_port`, `event_type`, `alert.signature` | Q13 |
| DS-004 | External threat intelligence and OSINT | VirusTotal detection and community pages; Microsoft documentation; vendor and community reports | Q1, Q2, Q9, Q12 |

## Usage Notes

- Findings cite the question number and, where relevant, the screenshot or field statistics they rest on.
- Queries are reproduced exactly as recorded in [Analysis Tools and Methods](../case-notes/analysis-tools-and-methods.md).
- Indicators are defanged in prose and tables.

## Enrichment

- `Botnet` and `Cerber.Botnet` are Fortigate UTM enrichment values (`appcat`, `app`) on traffic to destination port 6892 (Q10, Q11).
- The Q13 alert is a Suricata rule match. The recorded answer gives the signature as `ET POLICY Possible External IP Lookup ipinfo.io`; the analyst's notes give it as `ET INFO External IP Lookup`. Both are shown wherever it is cited.
- The malware family `Cerber` comes from VirusTotal (Q9); its description as ransomware comes from OSINT (Q12).

## Handling Limitations

- Collection dates for the searches and screenshots are not recorded.
- The record documents the searches run and the results viewed. It does not document how the underlying data was handled, so this inventory makes no assertion about it.
- Screenshots referenced by this case are not published in this repository.
