# Timeline – OSK Hijack Persistence and Cerber Botnet Activity

**Document Type:** Timeline  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Evidence Basis

Entries come from the analyst's notes and screenshots for the thirteen questions. Each carries its source and one of these time classes:

- **Display time, no timezone designation** — a time shown by Splunk for an event reproduced in the notes.
- **Device time, no timezone designation** — a date or time written inside the log text of that event.
- **No recorded time** — a value the record gives without a date or time.

No time value in the record carries a UTC designation, and none is converted here. Despite the file name, entries are reproduced as recorded, not as UTC values.

## Timestamped Observations

The record contains one case-event timestamp: the Fortigate UTM event reproduced in the Q10 notes.

### Q10 Fortigate Event — Display and Device Time, No Timezone Designation

| Recorded time | Time class | Event | Label |
|---|---|---|---|
| `8/24/164:49:41.000 PM` | Display time, no timezone designation | Fortigate UTM event: source `192[.]168[.]250[.]100` port 50720, destination `85[.]93[.]63[.]252` port 6892, protocol 17 (`udp/6892`), `appcat` Botnet, `app` Cerber.Botnet, action pass | Observed; External enrichment |
| `Aug 24 10:49:41`; `date=2016-08-24 time=10:49:40` | Device time, no timezone designation | Same event, as written in the log text | Observed |

The display value is recorded as `8/24/164:49:41.000 PM`, without a space between the date and the time.

### Q9 Community Entries — Relative Display Age, Not an Event Time

Two VirusTotal community entries quoted in the Q9 notes show the relative age `9 months ago`.
These are display ages of external enrichment, not times of case activity, and they are not used to place any event.

## Established Events Without Recorded Times

Rows are listed by question number. That order is not a chronology: the record gives these events no times.

| Event | Source | Label |
|---|---|---|
| 49,608 events containing `osk.exe` in the Windows event log search | Q3 query and answer | Observed; Range-accepted |
| `osk.exe` as the `Image` value `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe` in 49,594 events | Q4 answer and screenshot | Range-accepted; Observed |
| The suspicious binary's events carry host `we8105desk[.]waynecorpinc[.]local`, internal address `192[.]168[.]250[.]100` and user `bob.smith` | Q5 answer | Range-accepted |
| Destination ports 6892 (48,196 events, 99.998%) and 80 (1 event, 0.002%), among events carrying `DestinationPort` (97.156%) | Q6 screenshot and answer | Observed; Range-accepted |
| 16,384 distinct destination addresses of connection attempts on port 6892 | Q7 query and answer | Range-accepted |
| SHA-256 `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B` extracted from the `Hashes` field of Image Loaded (Event ID 7) events | Q8 query and answer | Range-accepted |
| VirusTotal detections name the malware family `Cerber` | Q9 answer and notes | Range-accepted; External enrichment |
| Fortigate UTM gives `appcat` Botnet and `app` Cerber.Botnet for traffic to destination port 6892 | Q10 and Q11 answers | Range-accepted; External enrichment |
| OSINT describes Cerber's primary function as ransomware | Q12 answer | Range-accepted; External enrichment |
| The single port-80 connection's destination `54[.]148[.]194[.]58`; Suricata signature recorded as `ET POLICY Possible External IP Lookup ipinfo.io` (answer) and `ET INFO External IP Lookup` (notes) | Q13 notes and answer | Observed; Range-accepted; External enrichment |

## Limitations

- No time in the record carries a timezone designation, and none is converted.
- The Q10 event's display time and device time are six hours apart, and the record gives no timezone for either.
- The Q10 event is the only recorded case-event timestamp. The Q9 relative ages describe external enrichment and do not order case activity.
- Events without recorded times are not placed in a sequence.
- Collection dates for the searches and screenshots are not recorded.
