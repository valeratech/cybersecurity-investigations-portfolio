# Cybersecurity Investigations Portfolio

This repository is a central collection of my cybersecurity investigations completed across various CyberRanges and lab environments. It serves as a structured record of hands-on **DFIR, SIEM investigation, threat hunting, memory, disk, and network forensics** work across multiple training platforms.

Current investigations include (but are not limited to):

- **SANS/NetWars**: Specialized technical mastery and advanced incident handling  
- **Hack The Box**: Dedicated SOC and DFIR investigative labs  
- **CyberDefenders**: Artifact-driven challenges centered on real-world memory, endpoint, and network forensics  
- **Security Blue Team (BTLO)**: Operationally-focused labs simulating real-world Security Operations Center (SOC) environments  
- Additional **self-built investigations** and forensic exercises  

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

## Repository Structure

```text
cybersecurity-investigations-portfolio/
├── README.md
├── TEMPLATE_Investigation_Report.md
└── cyber_range_investigations/
    ├── 0001-macro-malware-data-exfiltration/
    └── ...
