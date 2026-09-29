# Evidence Inventory – TeamCity APT Ransomware Investigation

**Document Type:** Evidence Inventory  
**Case ID:** 010-teamcity-apt-ransomware-lateral-movement  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Investigation Scope

This investigation was conducted as a structured CyberRange question set using the artifacts available within the range. The investigation concluded when the final question was answered. Evidence or analysis outside the scope of those questions was not collected and is not treated as missing or pending investigative work.

## Evidence Register

| Evidence ID | Description | Form | Contents |
|---|---|---|---|
| EV-001 | Analyst notes for the 38-question set | Document | Lab title, scenario and investigation scope; for each question: question text, hints, the recorded answer where one is recorded, analyst notes, and the KQL queries used |
| EV-002 | Screenshots in EV-001 | Images embedded in EV-001 | 44 screenshot references on 35 pages: Kibana field statistics, Discover rows and event messages, a network-diagram excerpt and web-decoder output |

## Data Sources Shown in the Record

These are the data sources that the queries and views in EV-001 and EV-002 reference. They are listed as sources, not as retained evidence; exports of them are not part of the case record.

| Source ID | Source | Events or fields | Questions |
|---|---|---|---|
| DS-001 | Sysmon | Event IDs 1 (process creation), 7 (image loaded) and 11 (file creation) | Q1, Q9, Q28, Q35, Q37 |
| DS-002 | PowerShell script-block logging | Event ID 4104; `powershell.file.script_block_text`, `message` | Q7 |
| DS-003 | Windows Security log | Event ID 4698; Event ID 4688 appears in a recorded query | Q18, Q37 |
| DS-004 | Task Scheduler operational log | Event IDs 106, 200 and 201 | Q17 |
| DS-005 | MSSQL log on the SQL server | Event IDs 18456 and 15457 | Q23, Q24 |
| DS-006 | HTTP data behind the NGINX reverse proxy | `nginx_rp` data view; `http.request.referrer`, `url.full` | Q3 |
| DS-007 | External tools | Web Base64 decoder (base64decode.org), IP lookup, MITRE ATT&CK pages | Q6, Q7, Q10, Q13, Q28 |

## Usage Notes

- Findings cite the question number and, where relevant, the screenshot or field statistics they rest on.
- Queries are reproduced exactly as recorded in [Analysis Tools and Methods](../case-notes/analysis-tools-and-methods.md), with typographic normalisation only (zero-width spaces removed, curly quotes straightened).
- Indicators are defanged in prose and tables; recorded queries and commands appear as recorded inside code blocks.
- The Q9 tunnel password is recorded in EV-001 (the Q9 answer and one screenshot) and is withheld from this case.

## Enrichment

- `ec2-3-90-168-151[.]compute-1[.]amazonaws[.]com` is the recorded answer to Q6, which asks for the name that IP lookup tools return for the attacker address.
- T1562.001 (Q7) and T1620 (Q28) are recorded answers; the notes link each to its MITRE ATT&CK page.
- `Cobalt Strike` appears only in question and hint wording (the Q28 question; the Q25 and Q37 hints).

## Handling Limitations

- Collection dates for the queries and screenshots are not recorded.
- The record documents the queries run and the results viewed. It does not document how the underlying data was handled, so this inventory makes no assertion about it.
- Screenshots referenced by this case are not published in this repository.
