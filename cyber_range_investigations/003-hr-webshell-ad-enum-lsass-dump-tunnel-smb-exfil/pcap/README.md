# PCAP Evidence — Access Notes

**Case ID:** 003  
**Case Title:** HR Webshell → AD Enum → LSASS Dump → Tunnel Pivot → SMB Exfil  
**Author:** Ryan Valera  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Purpose

This directory documents the status, accessibility, and handling of network packet capture (PCAP) evidence for this investigation.

## PCAP Availability

- The primary PCAP used in this investigation was provided **within the CyberDefenders CyberRange virtual environment**.
- Direct export or download of the raw PCAP file was **not permitted** by the platform.
- As a result, no PCAP files are stored in this repository.

## Analysis Methodology

Despite the lack of direct PCAP export, full network analysis was performed using:

- **Brim / Zui** for log-driven traffic exploration
- **Zeek** logs (`files.log`, SMB metadata, HTTP transactions)
- **Wireshark** GUI for packet-level inspection, stream reconstruction, and object extraction
- **Suricata** alert signatures for initial triage and correlation

All findings documented in the `analysis/` directory were derived from **direct inspection of the PCAP within the CyberRange environment**.

## Evidence Integrity Considerations

- The PCAP remained unmodified within the controlled CyberRange VM.
- All timestamps referenced in analysis were normalized to **UTC**.
- Findings are reproducible by reloading the same CyberRange scenario and applying documented filters and techniques.

## Notes

In real-world DFIR investigations, raw PCAPs are typically preserved with cryptographic hashes and formal chain-of-custody documentation. Platform-imposed restrictions in training environments may limit exportability; these constraints are transparently documented here.

**End of PCAP Access Notes**
