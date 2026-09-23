# Case-Notes-00-Intake

**Document Type:** Case Note  
**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## 1. Evidence Received

The documented investigation start date is `2026-02-26`.

### Primary Evidence
- Memory Image: `Server.raw`, supplied by the range

### Evidence Type
- Windows 10 x64 memory capture, profile `Win10x64_17763`

### Recorded Image Timestamp (UTC)
- `2025-05-27 09:30:20`, as reported by Volatility `imageinfo`

This is the timestamp the image reports for itself. No separate acquisition record,
custody entry or hash accompanies the image in this investigation, and none is available.

## 2. Evidence Handling

The investigation record documents the commands run against the image and the artifacts
they produced. It does not document acquisition method, storage configuration, access
controls or integrity verification for `Server.raw`, so no assertion about those controls
is made here.

## 3. Initial Context Provided

Range-supplied: a suspected compromise across multiple on-premises systems, with this
memory image representing one affected machine.

Questions defining the investigation covered:

- The recorded image timestamp
- The internal source address of the RDP connection
- The RDP port values
- A renamed discovery tool
- A service name and the executable it launches
- The full command line of the credential-dumping binary
- The lateral-movement command
- The SID associated with the reported activity

## 4. Initial Triage Actions Performed

### Memory Profiling

Command executed:
```
python vol.py -f ..\..\Server.raw imageinfo
```

Profile reported: `Win10x64_17763`, with four further suggestions listed by the tool.

### KDBG Validation

Command executed:
```
python vol.py -f ..\..\Server.raw --profile=Win10x64_17763 kdbgscan
```

Output reported `KDBG owner tag check: True`, `PsActiveProcessHead` with 79 processes and
`PsLoadedModuleList` with 163 modules.

### Event Log Extraction

Command executed:
```
python vol.py -f ..\..\Server.raw --profile=Win10x64_17763 dumpfiles --regex .evtx$ --ignore-case --dump-dir output
```

The extraction yielded `.vacb` cache fragments rather than complete `.evtx` files. The
fragments were renamed to `.evtx` and parsed with EvtxECmd for review in Timeline Explorer.
The rename step is documented in the notes as an example approach rather than as a
transcript of the exact commands run.

## 5. Observations Carried Forward

- The recorded image timestamp bounds the contents of the image.
- Event coverage is partial because the logs were reconstructed from `.vacb` fragments.
- An RDP connection from `192[.]168[.]19[.]159` was accepted on the host.
- A service creation record names `FireFox Update`.
- An LSASS-dumping command string and a WMIC command string were recovered from memory
  strings output.

## 6. Intake Outcome

- Memory profile identified and validated
- EVTX artifacts extracted and parsed
- Findings and their evidentiary limits recorded in
  [Initial Findings](../analysis/initial-findings.md) and
  [Timeline](../analysis/timeline.md)
