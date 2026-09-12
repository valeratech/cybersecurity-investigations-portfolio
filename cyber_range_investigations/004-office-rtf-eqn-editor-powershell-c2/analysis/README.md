# Analysis Directory — Case 004

**Document Type:** Directory Index  
**Case ID:** 004-office-rtf-eqn-editor-powershell-c2  
**Source Platform:** CyberDefenders CyberRange  

## Purpose of This Directory

The `analysis/` directory documents the **detection logic and filter criteria**
applied during Case 004. The filter lists are reconstructions of the process
the notes describe, not preserved filter syntax.

Command and query syntax preserved in the notes is in `../scripts/`.

Narrative context and conclusions are documented in:
- `case-notes/`
- `reports/final-report.md`

## File Index

### `sysmon-filters.md`
**Purpose:**  
Documents Sysmon event IDs, filters, and investigative logic used to isolate:
- Process execution
- Network connections
- Registry-based persistence
- Startup folder persistence

**Event IDs Referenced:**
- 1 (Process Create)
- 3 (Network Connection)
- 11 (File Create)
- 13 (Registry Value Set)

## Usage Notes

- All timestamps referenced in analysis outputs are treated as **UTC**
- Files in this directory are **non-executable** and **safe to store in a public repository**
- Indicators and command strings are **defanged** where applicable to prevent AV/EDR triggers

## Record Statement

The filter criteria recorded here describe how events were isolated during the
investigation. The originating CyberRange environment is closed, so they cannot
be re-applied against the original evidence.

## Status

Analysis artifacts for Case 004 are complete. The investigation is closed and
no additional range evidence is available.
