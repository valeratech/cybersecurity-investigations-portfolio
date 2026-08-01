# Evidence Handling & Platform Limitations

**Case ID:** 003  
**Author:** Ryan Valera  
**Platform:** CyberDefenders CyberRange  
**Time Standard:** UTC  

## CyberRange Evidence Constraints

This investigation was conducted entirely within a managed CyberRange environment. As a result:

- Raw PCAP files were not exportable
- Evidence acquisition followed platform-defined workflows
- Certain artifacts (e.g., LSASS dump) were accessed logically rather than physically

## Validation Approach

Despite export limitations, evidence integrity was maintained through:

- Multi-tool correlation (Suricata, Zeek, Wireshark)
- Reproducible filtering and queries
- Consistent timestamps across tools
- Cross-verification of alerts, streams, and extracted artifacts

## Chain-of-Custody Considerations

Formal chain-of-custody documentation is not applicable in CyberRange scenarios. However:

- Evidence origin is known and controlled
- No external manipulation occurred
- Findings are reproducible within the same lab environment

## Applicability to Real-World DFIR

While CyberRange environments impose constraints, the investigative methodology mirrors real-world DFIR practices, including:

- Evidence validation
- Timeline reconstruction
- Least-assumption analysis
- Clear documentation of limitations

**End of Document**
