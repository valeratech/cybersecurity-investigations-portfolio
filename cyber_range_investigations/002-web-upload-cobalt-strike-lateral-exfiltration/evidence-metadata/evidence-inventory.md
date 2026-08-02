# Evidence Register

**Case ID:** 002  
**Time Standard:** UTC  

| Evidence ID | Description | Source | Format | Hash | Notes |
|------------|------------|--------|--------|------|-------|
| E-001 | Network packet capture | CyberDefenders CyberRange | PCAP | Not recorded | Primary evidence source. Capture was not exportable from the range and was analysed in situ, so no hash was taken. |
| E-002 | Malicious payload `Urgent Support.iso` | Extracted from PCAP via Wireshark HTTP object export | ISO | SHA-256 `935492b3714f140ff4567c14fe0fc13cba6f5df13a2be8a8b14912f2da24d475` | Hashed with `sha256sum` during analysis. Submitted to VirusTotal; see Enrichment below. |

## Usage Notes

E-001 (PCAP) used for initial alert triage and stream inspection (Step 1).
E-002 (ISO) extracted from the capture, hashed, and submitted for reputation
and rule-based analysis.

## Enrichment

VirusTotal analysis of E-002:

- Detection ratio at time of lookup: 12 / 60
- Detection timestamp: 2023-02-20 19:06 UTC
- Community YARA match (THOR APT Scanner, signature-base ruleset):
  `CobaltStrike_Resources_Artifact64_v3_14_to_v4_x`

The detection timestamp is post-analysis enrichment recorded three days after
the observed activity and is deliberately excluded from the activity timeline.
