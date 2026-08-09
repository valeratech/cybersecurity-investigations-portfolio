# Analysis Directory — Case 004

**Document Type:** Directory Index  
**Case ID:** 004-office-rtf-eqn-editor-powershell-c2  
**Source Platform:** CyberDefenders CyberRange  

## Purpose of This Directory

The `analysis/` directory contains **reproducible analytical artifacts** used to derive findings in Case 004.  
Files here prioritize **exact detection logic and filters** over narrative explanation.

Reproducible commands and queries are in `../scripts/`.

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

## Reproducibility Statement

Another analyst with access to the same CyberDefenders CyberRange artifacts should be able to
apply the documented Sysmon filters and reach the same conclusions recorded in the case notes
and final report. Command- and query-level reproduction steps are documented in `../scripts/`.

## Status

Analysis artifacts for Case 004 are complete for the current scope.
Additional analysis files will be added here if new evidence is introduced.
