# Observed Timeline and Evidence Gaps

**Document Type:** Analysis  
**Case ID:** 002-web-upload-cobalt-strike-lateral-exfiltration  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Overview

This document records the attacker activity for which absolute timestamps were
retained, the activity that was established without a recoverable timestamp, and
the limits of what the retained evidence supports.

Entries are **observations**, not first occurrences. Where a signature fired
repeatedly, the timestamp below belongs to the specific record examined during
analysis. See Limitations.

## Timestamped Observations

| UTC Timestamp | Observation | Evidence Source |
|---|---|---|
| 2023-02-17 15:48:51.824499 | `Urgent Support.iso` uploaded via `POST /contact.php` from `113[.]26[.]232[.]2` to the web server `1[.]174[.]208[.]130` | Zeek `http.log`, uid `C1U5Ud12rO72abyc37` |
| 2023-02-17 16:37:34.813560 | SMB2 DLL-create / lateral-movement alert from `10[.]0[.]128[.]130` to `10[.]0[.]128[.]1:445` | Suricata alert, flow_id `452108344952417` |
| 2023-02-17 16:42:07.218533 | Cobalt Strike Beacon alert from `10[.]0[.]128[.]130` to `113[.]26[.]232[.]2:80` | Suricata alert, flow_id `9235882352841324` |
| 2023-02-17 16:42:08 | HTTP `200 OK` returned by C2 for `/en_US/all.js` | HTTP response `Date` header |
| 2023-02-17 16:42:11 | Second HTTP `200 OK` returned by C2 in the sampled stream | HTTP response `Date` header |

## Established Events Without Recovered Timestamps

| Event | Supporting Evidence |
|---|---|
| Payload executed on the internal endpoint via `DOCUMENT.LNK` within the ISO | LNK contents recovered with `strings -e l` |
| Defender real-time monitoring disabled and `D:\ADOBE.exe` launched | Command recovered from `DOCUMENT.LNK`: `Set-MpPreference -DisableRealtimeMonitoring 1` |
| `wwwroot` directory accessed for transfer over SMB | Wireshark SMB exported objects, share `\\WWW\wwwroot` |
| Final suspicious RDP session lasted approximately 137 seconds | Wireshark Statistics → Conversations, TCP tab (duration only) |

## Limitations

The timestamps above represent retained observations, not necessarily first
occurrence. The Cobalt Strike Beacon and SMB2 alerts are samples drawn from
repeated activity — `ET MALWARE Cobalt Strike Beacon Observed` fired 14,317
times across the capture, and the SMB2 lateral-movement signature fired twice.
The retained beacon record at 16:42:07 therefore does **not** establish that
beaconing began after the 16:37:34 SMB observation; earlier beacon traffic may
have existed.

Exact timestamps for payload execution, the Defender modification, `wwwroot`
staging, and the final RDP session were not retained during analysis. Raw PCAP
was examined in situ within the CyberDefenders CyberRange and was not
exportable, so these cannot be reconstructed without re-running the exercise.

The VirusTotal detection timestamp for `Urgent Support.iso` (2023-02-20 19:06)
is post-analysis enrichment metadata recorded three days after the activity, and
is deliberately excluded from this timeline. It is recorded with the evidence
metadata for the case.
