# Analysis Tools and Methods

**Document Type:** Reference  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Purpose

This document lists the platforms, data sources and queries used in the recorded question set, and the methods applied. It reproduces queries exactly as recorded and makes no case findings.

## Platforms and Tools

### Splunk

- Searches run in the Search and Reporting app against the `botsv1` dataset (`index="botsv1"`), as the lab instructions require.

### VirusTotal

- SHA-256 submission and review of the Detection and Community pages (Q9).

### OSINT

- Microsoft documentation for the purpose of `osk.exe` (Q1), and OSINT searches for its expected path (Q2) and for Cerber's primary function (Q12).

## Data Sources

- Windows event logs in XML (Sysmon telemetry), sourcetype `XmlWinEventLog` (Q3 to Q8, Q13).
- Fortigate UTM logs, sourcetype `fortigate_utm` (Q10, Q11).
- Suricata logs, sourcetype `suricata` (Q13).

## Query Language

Splunk Search Processing Language (SPL).

## Recorded Queries

Each query is reproduced as recorded. The record gives several searches in two spellings of the sourcetype value, `xmlwineventlog` in the query tables and `XmlWinEventLog` in the step breakdowns; each query below is reproduced in one recorded form.

### Q3 — Event Count for `osk.exe`

```text
index="botsv1" sourcetype=xmlwineventlog "osk.exe" | stats count
```

### Q4 — Image Path of `osk.exe`

```text
index="botsv1" sourcetype=xmlwineventlog "osk.exe"
```

The `Image` field of the returned events was reviewed.

### Q5 — Host, Address and User

```text
index="botsv1" sourcetype=XmlWinEventLog "osk.exe"
```

The `Computer`, `SourceIp` and `User` fields were reviewed.

### Q6 — Destination Ports

```text
index="botsv1" sourcetype=xmlwineventlog "osk.exe"
```

The `DestinationPort` field summary was reviewed and captured in the Q6 screenshot.

### Q7 — Distinct Destination Addresses on Port 6892

```text
index="botsv1" sourcetype=xmlwineventlog "osk.exe" DestinationPort=6892 DestinationIp=*| stats dc(DestinationIp)
```

### Q8 — SHA-256 from Image Loaded Events

```text
index="botsv1" sourcetype=xmlwineventlog EventCode=7 ImageLoaded="*osk.exe*"
```

The `Hashes` field of the returned events was reviewed.

### Q10 and Q11 — Fortigate UTM on Port 6892

```text
index="botsv1" sourcetype=fortigate_utm dest_port=6892
```

The `appcat`, `app` and `msg` fields were reviewed.

### Q13 — Port-80 Connection and Suricata Alert

Step 1, the port-80 event in the Windows event logs:

```text
index="botsv1" sourcetype=XmlWinEventLog "osk.exe" DestinationPort=80
```

Step 2, Suricata events for that destination:

```text
index="botsv1" sourcetype=suricata dest_ip=54.148.194.58 dest_port=80
```

Optional filter, alert events only:

```text
index="botsv1" sourcetype=suricata dest_ip=54.148.194.58 dest_port=80 event_type=alert
```

Questions 1, 2, 9 and 12 used OSINT or VirusTotal rather than a Splunk query.

## Analytical Methods

### Baseline Comparison

- The legitimate purpose and expected path of `osk.exe` were established by OSINT (Q1, Q2) and compared with the observed `Image` path (Q4).

### Aggregation

- `stats count` gave the event total (Q3); `stats dc(DestinationIp)` gave the distinct destination count on port 6892 (Q7).

### Field Pivoting

- Field values and field summaries led from the event set to the path, host, address, user, ports and hash (Q4 to Q8).

### Cross-Source Pivoting

- Destination port 6892 was carried from the Sysmon events to the Fortigate UTM search (Q10). The port-80 destination address was carried to the Suricata search (Q13), where the Sysmon field `DestinationIp` corresponds to `dest_ip`.

### Hash Lookup

- The SHA-256 from Q8 was submitted to VirusTotal (Q9).

## Notes

- Collection dates for the searches are not recorded.
