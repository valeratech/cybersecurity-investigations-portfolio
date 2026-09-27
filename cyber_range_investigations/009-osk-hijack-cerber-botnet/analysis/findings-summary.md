# Findings Summary – OSK Hijack Persistence and Cerber Botnet Activity

**Document Type:** Findings Summary  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Provenance Labels

Each finding states what the analyst's notes and screenshots carry:

- **Observed** — shown in the analyst's recorded results, field statistics or screenshots.
- **Range-supplied** — stated by the lab title or scenario, or by the wording of a question.
- **Range-accepted** — the answer recorded for a numbered question.
- **External enrichment** — a detection-rule match, a firewall classification, or a VirusTotal or OSINT attribution.
- **Analyst inference** — reasoned by the analyst from the above, and marked as such.
- **Not established** — the record does not support the statement.

No confidence rating is assigned, at case level or per finding.

## Executive Summary

The range titles this lab "Cerber Ransomware Persistence via OSK Hijack". Across thirteen questions, the record shows:

- a binary named `osk.exe` running from a user-profile `AppData\Roaming` folder rather than `C:\Windows\System32`;
- 49,608 events containing `osk.exe`, and the host, internal address and user they carry;
- destination ports 6892 and 80, and 16,384 distinct destination addresses of connection attempts on port 6892;
- a SHA-256 that VirusTotal associates with the Cerber family, which OSINT describes as ransomware;
- Fortigate UTM classifications Botnet and Cerber.Botnet for the port-6892 traffic;
- a single port-80 connection to an address for which a Suricata alert fired, with two differing recorded signature values.

The record does not order these events or link them in a chain. It does not establish persistence, a registry mechanism, how the binary arrived, or any encryption or other impact.

## Finding 1 – Masquerading Binary (Q2, Q4)

**Range-accepted.** The suspicious executable ran from `C:\Users\bob.smith.WAYNECORPINC\AppData\Roaming\{35ACA89F-933F-6A5D-2776-A3589FB99832}\osk.exe` (Q4). The legitimate On-Screen Keyboard is expected in `C:\Windows\System32` (Q2).

**Observed.** The `Image` field summary shows the suspicious path in 49,594 events (99.972%).

**Analyst inference.** The notes read the name-location mismatch and the GUID-like folder as a masquerading executable.

## Finding 2 – Host Context (Q5)

**Range-accepted.** Computer `we8105desk[.]waynecorpinc[.]local`, internal address `192[.]168[.]250[.]100`, user `bob.smith`.

## Finding 3 – Event Volume (Q3)

**Range-accepted.** 49,608 events contain `osk.exe` in the Windows event log search.

**Analyst inference.** The notes read this volume as unusual for an accessibility tool.

## Finding 4 – Destination Ports and Distinct Destinations (Q6, Q7)

**Observed.** Port 6892 in 48,196 events (99.998%) and port 80 in 1 event (0.002%), among events carrying `DestinationPort` (97.156%).

**Range-accepted.** 16,384 distinct destination addresses of connection attempts on port 6892.

**Analyst inference.** The notes read the pattern as consistent with automated scanning or botnet-like behaviour.

## Finding 5 – Hash and Malware Family (Q8, Q9, Q12)

**Range-accepted.** SHA-256 `37397F8D8E4B3731749094D7B7CD2CF56CACB12DD69E0131F07DD78DFF6F262B` (Q8); family Cerber (Q9); primary function Ransomware (Q12).

**External enrichment.** The family comes from VirusTotal detections, and its description as ransomware from OSINT.

## Finding 6 – Firewall Classification (Q10, Q11)

**Range-accepted.** Fortigate UTM assigns `appcat` Botnet (Q10) and `app` Cerber.Botnet (Q11) to traffic to destination port 6892.

**External enrichment.** These are Fortigate classification labels; the one event reproduced in the notes shows action pass.
They do not establish communication with botnet infrastructure.

## Finding 7 – Port-80 Connection and Suricata Alert (Q13)

**Observed.** The single port-80 event's destination is `54[.]148[.]194[.]58`.

**Range-accepted.** The Suricata signature is recorded as `ET POLICY Possible External IP Lookup ipinfo.io`; the analyst's notes give `ET INFO External IP Lookup`. The values differ and are not reconciled.

**Analyst inference.** The notes read the alert as an attempt to discover the system's public IP address, associated with reconnaissance.

## Assessment

**Analyst inference.** The record supports a masquerading binary named `osk.exe` on `we8105desk[.]waynecorpinc[.]local`, whose hash VirusTotal associates with Cerber and whose port-6892 traffic Fortigate labels Cerber.Botnet.
Persistence is range-supplied framing, from the lab title and Q1, not an observed finding. The record does not establish a registry mechanism, how the binary arrived, encryption or other impact, or any order among these events.
