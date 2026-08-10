# Evidence Register

**Document Type:** Evidence Inventory  
**Case ID:** 003-hr-webshell-ad-enum-lsass-dump-tunnel-smb-exfil  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose

This document records all evidence sources referenced during the investigation, including acquisition context, accessibility constraints, and integrity considerations. It supports transparency, reproducibility, and investigative accountability.

## Evidence Summary

| Evidence ID | Description | Source | Format | Hash | Notes |
|------------|-------------|--------|--------|------|------|
| E-001 | Network traffic capture (primary dataset) | CyberDefenders CyberRange | PCAP | N/A | PCAP accessed via CyberRange VM only |
| E-002 | Webshell upload artifact | Derived from PCAP analysis | HTTP | See Artifact Hashes | Observed via Suricata, Zeek, and Wireshark |
| E-003 | LSASS process memory dump | Compromised host | DMP | N/A | Extracted and analyzed within CyberRange |
| E-004 | Credential extraction output | Analyst-generated | TXT | N/A | Pypykatz output derived from LSASS dump |
| E-005 | Malicious payload | External C2 server | EXE | See Artifact Hashes | agent.exe analyzed via VirusTotal |

### Artifact Hashes

Digests are reproduced using the casing recorded by their originating tool.
Hexadecimal digest comparison is case-insensitive; source representation is
preserved for provenance rather than normalised for presentation.

**E-002 — `mycv.aspx`** (recorded by Zeek `files.log`)

- **MD5:** `2be86b49e21ebbbc1507ee5ac97f47e4`
- **SHA1:** `21cfe9efa65fd2a09aaf21cf633fb4160db1f62a`

**E-005 — `agent.exe`** (recorded by PowerShell `Get-FileHash`)

- **SHA256:** `DE1D26F43278CC17F0EFD464C04D687CDC872008F5C1251EA0AF3FB9E0A0E395`

## Evidence Accessibility Notes

- Raw PCAP files were **not directly exportable** from the CyberDefenders CyberRange environment.
- Analysis was performed **in situ** using:
  - Brim/Zui
  - Zeek logs
  - Wireshark GUI within the provided VM
- All findings were derived from **first-hand inspection of network traffic** inside the range.

## Integrity & Handling Considerations

- Evidence remained within the CyberRange environment at all times.
- No modification of original datasets occurred.
- Hashes are unavailable for platform-managed artifacts unless explicitly extracted.
- All timestamps referenced in analysis were normalized to **UTC**.

## Analyst Statement

All evidence referenced in this investigation was analyzed directly by the author within the CyberDefenders CyberRange environment. Limitations in evidence exportability were platform-imposed and are transparently documented above.

**End of Evidence Register**
