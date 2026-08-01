# Cybersecurity Investigations Portfolio

This repository is a central collection of my cybersecurity investigations completed across CyberRange and lab environments. It serves as a structured record of hands-on **DFIR, SIEM investigation, threat hunting, memory, disk, and network forensics** work.

Current investigations:

- **CyberDefenders** — 9 investigations: artifact-driven challenges centered on real-world memory, endpoint, and network forensics  
- **Security Blue Team (BTLO)** — 1 investigation: operationally-focused labs simulating real-world SOC environments  

All investigations follow a consistent methodology, typically including:

- Case objectives and scenario background  
- Evidence collection and structured forensic analysis  
- Detection logic and log analysis (**Splunk SPL, KQL, Sigma, Zeek, Suricata**)  
- Timeline reconstruction, IOCs, and attacker TTP mapping  
- Final findings and remediation recommendations  

## Investigation Methodology

Each investigation follows a structured, analyst-driven workflow:

- Data acquisition and initial triage  
- Log and artifact analysis (Splunk, endpoint, network, memory)  
- Query development and iterative refinement (SPL, KQL, etc.)  
- Event correlation and timeline reconstruction  
- Identification of suspicious patterns and attacker behavior  
- Validation of findings with supporting evidence  
- Documentation of results, including queries, reasoning, and conclusions  

> **Note:** All data in this repository is generated in lab environments or fully sanitized.  
> No real-world client or sensitive information is included.

## Case Status

- **Complete** — the cyber-range exercise was finished, its final question
  answered, and the portfolio report and supporting documentation finalised.
- **In Progress** — the exercise, analysis, evidence collection, or portfolio
  documentation remains unfinished.

Status describes the state of this repository's documentation, not a formal
closure process within the range platform.

## Date Fields

Documentation timestamps describe when the portfolio case study was written.
They are not investigation timestamps. Where the date of the underlying
range activity was not recorded, it is stated as such rather than inferred.

## Indicator Handling Convention

Indicators of compromise in this repository are **defanged** in prose, IOC
tables and inline references (`192[.]168[.]1[.]1`, `hxxp://`). Indicators
inside fenced code blocks are left in their original form so that documented
queries and filters remain directly runnable - re-fang deliberately before
reuse.

Recovered credential material is masked. Password hashes are truncated and
plaintext passwords are redacted; where password *characteristics* are
analytically relevant they are described rather than reproduced.

## Repository Structure

```text
cybersecurity-investigations-portfolio/
├── README.md
├── TEMPLATE_Investigation_Report.md
└── cyber_range_investigations/
    ├── 001-macro-malware-data-exfiltration/
    └── ...
```
