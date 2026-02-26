# Evidence Register

**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange – Memory Forensics Module  

## 1. Primary Evidence

| Evidence ID | Description        | File Name    | Source | Date Acquired (UTC) | SHA256 | Notes |
|------------|-------------------|--------------|--------|---------------------|--------|-------|
| EV-001     | Windows Memory Image | Server.raw | CyberDefenders | 2025-05-27 09:30:20 | Pending | Memory capture of suspected compromised host |

## 2. Derived Artifacts

| Artifact ID | Description | Source Evidence | Tool Used | Output Location | Notes |
|-------------|------------|----------------|-----------|----------------|-------|
| ART-001 | Extracted EVTX artifacts | EV-001 | Volatility `dumpfiles` | output/ | Extracted via regex `.evtx$` |
| ART-002 | Reconstructed EVTX from `.vacb` | ART-001 | PowerShell rename workflow | EVTX working directory | `.vacb` fragments converted |
| ART-003 | Parsed EVTX CSV logs | ART-002 | EvtxECmd | CSV output directory | Used for timeline reconstruction |
| ART-004 | Memory strings output | EV-001 | strings64.exe | parsed-server-raw-strings-file.txt | Used to identify command-line artifacts |

## 3. Evidence Handling Notes

- Original memory image preserved in read-only state.
- All analysis conducted on working copy.
- No evidence modification performed.
- Hash verification pending (to be calculated and recorded).
- EVTX artifacts reconstructed from memory; completeness not guaranteed.

## 4. Chain-of-Custody (CyberRange Context)

This investigation was conducted in a controlled CyberDefenders training environment.  
Evidence provided directly by platform for analysis.  

No real-world production systems involved.

## 5. Status

- Memory image validated
- EVTX artifacts extracted
- Initial artifacts cataloged
- Hash verification pending
