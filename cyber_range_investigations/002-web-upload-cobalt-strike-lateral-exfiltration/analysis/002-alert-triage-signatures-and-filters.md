# Alert Triage – Signatures, Filters, and Extracted Stream

**Document Type:** Analysis

**Case ID:** 002-web-upload-cobalt-strike-lateral-exfiltration  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Objective

Analyze IDS/IPS alert data to identify high-confidence indicators of compromise, prioritize suspicious traffic, and isolate potential command-and-control (C2) infrastructure.

## Alert Signature Counts (Initial View)

Collected from Suricata alert logs by signature frequency:

- ET HUNTING GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1 — 618  
- ET MALWARE Cobalt Strike Beacon Observed — 14317  
- ET POLICY SMB2 NT Create AndX Request For a DLL File - Possible Lateral Movement — 2  
- Additional Suricata alerts indicate anomalies across DNS, SMB, and TCP stream behavior  

## Queries / Filters Used (Zui-style)

### Base Alert Filter

`alert`

### Filter by Destination IP

`alert | dest_ip==113[.]26[.]232[.]2`

### Count by Destination IP
- Zui UI Method:
  - Right-click → Count by Field → `dest_ip`

### Count by Signature for Destination

`alert | dest_ip==113[.]26[.]232[.]2 | count() by alert.signature`

## Destination IP Distribution (Observed)

- 113[.]26[.]232[.]2 — 29870  
- 10[.]0[.]128[.]0 — 596  
- 10[.]0[.]128[.]3 — 294  
- 10[.]0[.]128[.]1 — 109  
- 10[.]0[.]128[.]130 — 96  
- 1[.]174[.]208[.]130 — 24  
- Missing destination IP — 34  

## Analysis Observations

- High-frequency alerting is concentrated on external IP `113[.]26[.]232[.]2`, indicating likely command-and-control (C2) infrastructure.  
- The volume of `ET MALWARE Cobalt Strike Beacon Observed` alerts strongly suggests persistent beaconing behavior.  
- Internal IP addresses (`10[.]0[.]128[.]x`) show lower-frequency alerting, potentially associated with lateral movement or internal communication.  
- SMB-related alerts indicate possible file transfer or DLL staging consistent with lateral movement techniques.  

## Extracted HTTP Stream (Beacon Example)
```
GET /en_US/all.js HTTP/1.1
Host: 113[.]26[.]232[.]2
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 0
```

## Interim Conclusion

- External host `113[.]26[.]232[.]2` is highly likely associated with Cobalt Strike C2 infrastructure.  
- Repeated HTTP requests with consistent user-agent strings and minimal response payloads are indicative of beaconing activity.  
- Alert distribution and protocol anomalies support further investigation into lateral movement and internal host compromise.  

## Next Steps

- Correlate beaconing intervals and session persistence  
- Identify originating internal host(s) communicating with C2  
- Map SMB activity to lateral movement timeline  
- Validate additional external infrastructure associated with attacker operations  
