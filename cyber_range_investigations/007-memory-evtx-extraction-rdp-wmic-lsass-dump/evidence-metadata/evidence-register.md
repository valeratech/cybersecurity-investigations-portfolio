# Evidence Register

**Document Type:** Evidence Inventory  
**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Investigation Scope

This investigation was conducted as a structured CyberRange question set using the artifacts available within the range. The investigation concluded when the final question was answered. Evidence or analysis outside the scope of those questions was not collected and is not treated as missing or pending investigative work.

## 1. Primary Evidence

| Evidence ID | Description | File Name | Source | Recorded Image Timestamp (UTC) | SHA256 | Notes |
|------------|-------------|-----------|--------|-------------------------------|--------|-------|
| EV-001 | Windows memory image | `Server.raw` | CyberDefenders CyberRange | 2025-05-27 09:30:20 | Not recorded | Timestamp is the value reported by Volatility `imageinfo`, not a separate acquisition record |

No hash of `Server.raw` is recorded in the investigation record. The value is not
available and is not a pending item.

## 2. Derived Artifacts

| Artifact ID | Description | Source Evidence | Tool Used | Output Location | Notes |
|-------------|-------------|-----------------|-----------|-----------------|-------|
| ART-001 | EVTX artifacts extracted from memory | EV-001 | Volatility `dumpfiles` | `output/` | Extracted with `--regex .evtx$ --ignore-case`; output was `.vacb` cache fragments rather than complete `.evtx` files |
| ART-002 | `.vacb` fragments renamed to `.evtx` | ART-001 | PowerShell | EVTX working directory | The notes record the rename as an example approach, not a transcript of the exact commands executed |
| ART-003 | Parsed EVTX CSV output | ART-002 | EvtxECmd | CSV output directory | Reviewed in Timeline Explorer; source of the event records cited in the analysis documents |
| ART-004 | Memory strings output | EV-001 | `strings64.exe` | `parsed-server-raw-strings-file.txt` | Source of the recovered `DD.exe` and `wmic` command strings |

## 3. Handling and Usage Notes

- The investigation record documents the commands run and the artifacts produced. It does
  not document acquisition method, storage configuration, access controls or integrity
  verification for `Server.raw`, so this register makes no assertion about them.
- EVTX coverage is partial by construction: the logs were reconstructed from `.vacb`
  cache fragments, and the extent of the gap is not measurable from the surviving record.
- ART-004 contains command strings recovered from memory. A recovered string records a
  command line present in memory; it does not establish that the command executed or
  completed.
- One credential appears in the recovered WMIC command string. It is withheld from all
  published content, where it is rendered as `<REDACTED>`.
- Indicators are defanged in prose and tables. Original forms appear only inside fenced
  blocks where exact syntax matters.

## 4. Range Context

This investigation was conducted in a CyberDefenders training environment. The memory image
was provided by the platform for analysis.

## 5. Register Status

- Primary evidence recorded
- Derived artifacts recorded with the tool that produced each
- Evidentiary limits recorded against the artifacts they affect
