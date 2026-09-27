# Network Analysis

**Document Type:** Analysis  
**Case ID:** 009-osk-hijack-cerber-botnet  
**Time Standard:** UTC  
**Source Platform:** Security Blue Team CyberRange  

## Objective

This document sets out the network activity the record associates with the suspicious binary, and the enrichment Fortigate UTM and Suricata applied to it.

## Data Sources

- Windows event logs in XML (Sysmon telemetry): the `DestinationPort` and `DestinationIp` fields (Q6, Q7, Q13).
- Fortigate UTM logs (Q10, Q11).
- Suricata logs (Q13).

## Destination Ports (Q6)

### Observation

**Observed.** The `DestinationPort` field summary shows 2 values across 97.156% of events: 6892 in 48,196 events (99.998%) and 80 in 1 event (0.002%), with minimum 80 and maximum 6892.
**Range-accepted.** 6892, 80.

### Analyst Interpretation

**Analyst inference.** The notes read port 6892 as the primary channel and suggest custom-service or command-and-control communication on it; they read the single port-80 event as possible fallback, beacon or test traffic.

## Distinct Destinations on Port 6892 (Q7)

### Observation

**Range-accepted.** 16,384 distinct destination addresses of connection attempts on port 6892, from `stats dc(DestinationIp)`.

### Analyst Interpretation

**Analyst inference.** The notes read the count as consistent with automated scanning, mass network probing, or worm-like or botnet activity.

### Limits

The question text calls these addresses external infrastructure; the record does not list them or show where they are.

## Port-80 Connection and Suricata Alert (Q13)

### Observation

**Observed.** The single port-80 event's destination is `54[.]148[.]194[.]58`.
**Range-accepted.** The Suricata alert signature for events to that destination is recorded as `ET POLICY Possible External IP Lookup ipinfo.io`; the analyst's notes give it as `ET INFO External IP Lookup`. The two recorded values differ, and both are preserved wherever the signature is cited.

### Analyst Interpretation

**Analyst inference.** The notes interpret the alert as an attempt to discover the system's public IP address, which they associate with malware reconnaissance.
The signature is a rule match; no DNS query or HTTP request content is recorded.

## Fortigate UTM Classification (Q10, Q11)

### Observation

**Range-accepted.** For traffic to destination port 6892, Fortigate UTM assigns `appcat` Botnet (Q10) and `app` Cerber.Botnet (Q11).
**Observed.** The notes reproduce one Fortigate event, displayed as `8/24/164:49:41.000 PM` with no timezone designation: source `192[.]168[.]250[.]100` port 50720, destination `85[.]93[.]63[.]252` port 6892, protocol 17 (`udp/6892`), action pass, application list Honeypot-Access, `crscore` 50, `crlevel` critical. Its message field is truncated in the record.

### Limits

Category and application names are enrichment labels. They do not establish communication with botnet infrastructure, and the one reproduced event shows the traffic passed.

## Assessment

**Analyst inference.** The recorded network activity is dominated by connection attempts to port 6892 across 16,384 distinct destinations, which Fortigate labels Cerber.Botnet. The notes read this as consistent with botnet-like or scanning behaviour.
