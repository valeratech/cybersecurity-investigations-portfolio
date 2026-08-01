# Case-Notes-00-Intake

**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Investigation Start Date:** 2026-02-26  
**Analyst:** Ryan Valera  
**Source Platform:** CyberDefenders CyberRange – Memory Forensics Module  
**Time Standard:** UTC  

## 1. Evidence Received

### Primary Evidence
- Memory Image: `Server.raw`

### Evidence Type
- `Windows 10 x64` memory capture

### Reported Image Timestamp (UTC)
- 2025-05-27 09:30:20

## 2. Evidence Handling Notes

- Evidence stored in read-only analysis directory.
- No modifications performed on original memory image.
- All analysis conducted on working copy.
- Hash verification to be computed and recorded (SHA256 pending).

## 3. Initial Context Provided

A suspected compromise across multiple on-premises systems.  
This memory image represents one affected machine.

Primary investigative objectives:

- Identify initial access vector.
- Extract Windows EVTX artifacts from memory.
- Determine attacker tooling and execution behavior.
- Identify persistence mechanisms.
- Confirm credential dumping.
- Trace lateral movement activity.
- Associate actions with responsible user context (SID).

## 4. Initial Triage Actions Performed

### Memory Profiling

Command executed:
```
python vol.py -f ..\..\Server.raw imageinfo
```

Profile identified:
- `Win10x64_17763`

### KDBG Validation

Command executed:
```
python vol.py -f ..\..\Server.raw --profile=Win10x64_17763 kdbgscan
```

Profile confirmed valid.

## 5. Observations

- Memory image timestamp aligns with suspected intrusion window.
- EVTX artifacts present but reconstructed from `.vacb` fragments.
- RDP activity observed from internal IP: `192[.]168[.]19[.]159`
- Suspicious service created: `FireFox Update`
- Evidence of credential dumping via `DD.exe`
- Lateral movement observed using WMIC.

## 6. Investigation Status

- Memory profile validated  
- EVTX artifacts extracted  
- Initial attacker activity identified  
- Persistence mechanism identified  
- Credential dumping confirmed  
- Lateral movement confirmed  
