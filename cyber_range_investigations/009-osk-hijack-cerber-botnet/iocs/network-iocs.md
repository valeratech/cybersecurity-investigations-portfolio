# Network Indicators of Compromise (IOCs)

**Document Type:** IOC Collection  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Malicious Indicators

Indicators the record ties to the suspicious binary, each with the basis the record gives for that tie.

| Indicator | Type | Basis in the record | Provenance |
|---|---|---|---|
| `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B` | SHA-256 | Recorded answer to Q8, extracted from the `Hashes` field of Image Loaded (Event ID 7) events matching `*osk.exe*`; VirusTotal detections name the family `Cerber` (Q9) | Range-accepted; External enrichment |
| `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe` | File path | Recorded answer to Q4; the `Image` value in 49,594 events (Q4 screenshot); outside the expected `C:\Windows\System32` (Q2) | Range-accepted; Observed |

## Affected Assets

| Asset | Type | Basis in the record | Provenance |
|---|---|---|---|
| `we8105desk[.]waynecorpinc[.]local` | Host | `Computer` value for the suspicious binary's events (Q5) | Range-accepted |
| `192[.]168[.]250[.]100` | Internal IPv4 address | `SourceIp` value for the same events (Q5); source address of the Fortigate event in the Q10 notes | Range-accepted; Observed |
| `bob.smith` | User account | `User` value for the same events (Q5) | Range-accepted |

## Detection Rule Matches

Rule matches and enrichment labels are external enrichment: each records what a detection or classification system reported, not that the behaviour it names occurred.

| Rule or label | Source | Basis in the record |
|---|---|---|
| `appcat` Botnet | Fortigate UTM | Traffic to destination port 6892; recorded answer to Q10 |
| `app` Cerber.Botnet | Fortigate UTM | Same traffic; recorded answer to Q11 |
| `ET POLICY Possible External IP Lookup ipinfo.io` (recorded answer) or `ET INFO External IP Lookup` (analyst's notes) | Suricata | Alert for the single port-80 destination; the two recorded values differ and are not reconciled (Q13) |
| Family `Cerber` | VirusTotal | Vendor detections for the SHA-256; recorded answer to Q9 |

## Contextual Observables — Not IOCs

Values that the record does not establish as attacker-controlled. They are recorded as context, with their provenance, rather than as indicators.

| Observable | Basis in the record | Provenance |
|---|---|---|
| `54[.]148[.]194[.]58` | Destination of the single port-80 event of the suspicious binary (Q13 notes); the Suricata signature names an external-IP-lookup service | Observed; External enrichment |
| `ipinfo[.]io` | Appears only in the recorded signature text; no DNS query or HTTP host value is recorded | External enrichment |
| `85[.]93[.]63[.]252` | Destination of the one Fortigate event reproduced in the Q10 notes: `udp/6892`, `appcat` Botnet, `app` Cerber.Botnet, action pass | Observed; External enrichment |
| Destination port 6892 | 48,196 events, 99.998% of events carrying `DestinationPort` (Q6); the Fortigate search pivot (Q10) | Observed; Range-accepted |
| Destination port 80 | 1 event, 0.002% (Q6); the connection examined in Q13 | Observed; Range-accepted |

## Notes

- The filename `osk.exe` alone is not an indicator: the legitimate On-Screen Keyboard binary has the same name.
- The 16,384 distinct destination addresses of connection attempts on port 6892 (Q7) are not enumerated in the record.
- Addresses are defanged per investigation standards.
- Indicators should be used for detection, correlation, and threat hunting activities.
