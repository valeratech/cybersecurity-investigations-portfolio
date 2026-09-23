# Timeline Reconstruction

**Document Type:** Timeline  
**Case ID:** 007-memory-evtx-extraction-rdp-wmic-lsass-dump  
**Time Standard:** UTC  
**Source Platform:** CyberDefenders CyberRange  

## Evidence Basis

Entries below are drawn from:

- EVTX artifacts extracted from `Server.raw` with Volatility `dumpfiles`
- `.vacb` fragments renamed to `.evtx` and parsed with EvtxECmd
- CSV output reviewed in Timeline Explorer
- Memory strings output from `strings64.exe`
- Volatility `imageinfo` metadata

Each entry states whether the time is carried by the artifact itself or derived.

### Time Basis

Values with an explicit UTC warrant:

- `imageinfo` reports `Image date and time : 2025-05-27 09:30:20 UTC+0000`.
- Sysmon records carry a `UtcTime` field, used for every Sysmon entry below.
Values recorded without a timezone designation:

- The RDP-CoreTS record carries `Time Created 2025-05-27 09:21:40`. The surviving excerpt
  supplies no timezone field, so the value is preserved as recorded and no conversion or
  UTC basis is asserted for it.

Range-accepted at minute precision: the image timestamp as `2025-05-27 09:30`.

No conversion was applied to any value below. Entries without a recorded time are marked
as such rather than placed by proximity.

## Observations — 2025-05-26 (Unattributed Host Activity)

This day's records concern memory-acquisition utilities. The surviving record does not
attribute them to the intruder, and does not document them as authorised administrative
work. They are reported as observed, unattributed activity.

### 12:32:38
- `chrome.exe` creates a temporary file under `C:\Users\Administrator\Downloads\`.

### 12:32:40
- `chrome.exe` creates `C:\Users\Administrator\Downloads\DumpIt.exe:Zone.Identifier`,
  recording a browser download of `DumpIt.exe`.

### 12:32:48
- `DumpIt.exe` creates `C:\Windows\SysWOW64\drivers\DumpIt.sys`.
- `DumpIt.exe` creates
  `C:\Users\Administrator\Downloads\WIN-2O66FDBAHOG-20250526-123246.raw`.

### 12:42:29 – 12:42:30
- `chrome.exe` creates a temporary file and
  `C:\Users\Administrator\Downloads\winpmem_mini_x64_rc2.exe:Zone.Identifier`.

### 12:48:06
- `Explorer.EXE` creates `C:\Users\Administrator\Tools\DumpIt.exe`.
- The artifact is a file-creation event. Whether the file was copied, moved or written
  afresh is not established.

## Observations — 2025-05-27

### 09:17:33 – 09:17:52
- Repeated native-image file creations by
  `C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorsvw.exe` under
  `C:\Windows\assembly\NativeImages_v4.0.30319_32\`.
- Consistent with routine .NET native-image compilation. Included for completeness; no
  malicious indicator is asserted.

### 09:21:40
- RDP-CoreTS `Event ID 131`: `RDP server accepted a new TCP connection` from
  `192[.]168[.]19[.]159:64984`, `Connection Type: TCP`.
- The event records connection acceptance. An authenticated interactive session is not
  established by it.
- The recorded time carries no timezone designation, so it is not ordered against the
  UTC-qualified Sysmon entries below.
- A second port value, `64989`, is recorded as the accepted answer for the port question.
  Both values are preserved; see Initial Findings, Finding 3.

### 09:21:58
- `Explorer.EXE` (process ID 1844, user `WIN-2O66FDBAHOG\Administrator`) creates under
  `C:\Users\Public\Downloads\N1\N1\`:
  - `DD.exe`
  - `SB.exe`
  - `tt.exe`
  - `n1.ps1`

### 09:22:22
- The same process creates the same four names under
  `C:\Users\Default\AppData\Local\Temp\N1\`.
- Whether this was a copy, a move or a separate write is not established.

### Time not established — Service Creation
- A service creation record carries `ServiceName: FireFox Update`,
  `StartType: auto start`, `AccountName: LocalSystem`, and
  `ImagePath: C:\Windows\System32\cmd.exe /c "powershell -WindowStyle Hidden -EncodedCommand <base64>"`.
- The decoded command is `Start-Process -FilePath 'C:\ProgramData\chocolatey\tt.exe'`.
- The surviving payload carries no timestamp field, so this entry is not placed on the
  clock. Whether the service started is not established.

### 09:23:45
- `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` creates
  `__PSScriptPolicyTest_ueoqn4r3.0np.ps1` under the Administrator temp directory.
- The artifact shows a PowerShell process active on the host. It does not identify what
  was run, and it does not tie the process to the service configured above.

### Time not established — Recovered Command Strings
- LSASS dump command recovered from memory strings:
  ```
  C:\Users\Default\AppData\Local\Temp\N1\DD.exe -accepteula -ma lsass.exe C:\Users\Default\AppData\Local\Temp\mm.tmp
  ```
- WMIC command recovered from memory strings:
  ```
  wmic /node:192.168.19.163 /user:noah /password:"<REDACTED>"
  ```
- Strings carry no timestamp. Neither command is placed on the clock, and execution is not
  established for either.

### Associated event payloads — time not recorded in the notes
- `C:\Windows\System32\wbem\WMIC.exe` with `IpAddress 192[.]168[.]19[.]163`,
  `IpPort 49667`, subject SID
  `S-1-5-21-2346552008-2584940806-3566241850-500`, subject `Administrator`, target user
  `noah`, target server `DESKTOP-U98A16J`.
- A second payload names `C:\Windows\System32\svchost.exe` with the same address and
  `IpPort 135`.

## Sequence Summary

### Established order — Sysmon observations with an explicit UTC basis

1. `09:21:58` — four files created under `C:\Users\Public\Downloads\N1\N1\`.
2. `09:22:22` — the same four names created under the Temp path.
3. `09:23:45` — a PowerShell process active on the host.

These three carry a `UtcTime` field from the same source, so their order relative to one
another is established.

### Not ordered against the sequence above

- The RDP connection acceptance, recorded as `09:21:40`. The value comes from a different
  source and carries no timezone designation, so its position relative to the UTC-qualified
  Sysmon entries is not established. It is not placed before, within or after them here.
- Service creation, the LSASS command and the WMIC command, none of which carries a
  recorded time at all.

## Limitations

- EVTX artifacts were reconstructed from `.vacb` fragments. Event coverage is partial by
  construction, and the size of the gap is not measurable from the record.
- The service creation record, both recovered command strings and the WMIC-related event
  payloads carry no timestamp in the surviving record.
- Creation events do not establish execution. No process-creation record survives for
  `DD.exe`, `SB.exe`, `tt.exe` or `n1.ps1`.
- The recorded image timestamp bounds what the image can contain. It is not evidence that
  activity ceased at that moment.
- The 2025-05-26 entries are unattributed. Reading them as attacker staging would exceed
  the record.
