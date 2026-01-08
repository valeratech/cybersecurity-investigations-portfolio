# Alert Triage – Signatures, Filters, and Extracted Stream

**Case ID:** 002  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Alert Signature Counts (Initial View)
(Collected from alert logs by signature)
- ET HUNTING GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1 — 618
- ET MALWARE Cobalt Strike Beacon Observed — 14317
- ET POLICY SMB2 NT Create AndX Request For a DLL File - Possible Lateral Movement — 2
- (additional Suricata stream/DNS/SMB anomalies observed)

## Queries / Filters Used (Zui-style)
- Filter alerts:
  - `alert`
- Filter by destination IP:
  - `alert | dest_ip==113.26.232.2`
- Count by destination IP:
  - Right-click → Count by Field → `dest_ip`
- Count by signature for destination:
  - `alert | dest_ip==113.26.232.2 | count() by alert.signature`

## Dest IP Count Output (as observed)
- dest_ip 113.26.232.2 — 29870
- dest_ip 10.0.128.0 — 596
- dest_ip 10.0.128.3 — 294
- dest_ip 10.0.128.1 — 109
- dest_ip 10.0.128.130 — 96
- dest_ip 1.174.208.130 — 24
- dest_ip missing — 34

## Extracted HTTP Stream Snippet (Beacon Example)
GET /en_US/all.js HTTP/1.1  
Host: 113.26.232.2  
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)  

HTTP/1.1 200 OK  
Content-Type: application/octet-stream  
Content-Length: 0  
