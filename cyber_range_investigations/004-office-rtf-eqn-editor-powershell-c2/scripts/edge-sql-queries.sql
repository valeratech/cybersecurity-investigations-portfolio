/*
Case ID: 004
Case Name: Office RTF (Equation Editor) → PowerShell Persistence → C2
Source Platform: CyberDefenders CyberRange
Purpose: Reproducible Microsoft Edge artifact analysis
Time Standard: UTC (unless CyberRange explicitly states otherwise)

NOTE:
- Queries are read-only
- Intended for Microsoft Edge Chromium SQLite databases
- Database paths reflect CyberRange-provided artifacts
*/

-- =========================================================
-- Query 1: Identify non-HTTPS URLs (potential phishing)
-- =========================================================
SELECT
    id,
    url,
    title,
    visit_count,
    typed_count,
    last_visit_time
FROM urls
WHERE url LIKE '%http%'
  AND url NOT LIKE '%https%'
ORDER BY last_visit_time DESC;


-- =========================================================
-- Query 2: Identify downloaded files
-- =========================================================
SELECT
    id,
    guid,
    target_path,
    current_path,
    start_time,
    received_bytes,
    total_bytes,
    state,
    interrupt_reason,
    end_time,
    opened,
    referrer,
    tab_url,
    mime_type,
    original_mime_type
FROM downloads
ORDER BY start_time DESC;


-- =========================================================
-- Query 3: Identify downloads from suspicious domains
-- =========================================================
SELECT
    id,
    guid,
    target_path,
    start_time,
    referrer,
    tab_url,
    mime_type
FROM downloads
WHERE referrer LIKE '%supportmlcrosoft%'
   OR tab_url LIKE '%supportmlcrosoft%'
ORDER BY start_time DESC;


-- =========================================================
-- Query 4: Correlate URL visits with download activity
-- =========================================================
SELECT
    u.url,
    u.title,
    u.last_visit_time,
    d.target_path,
    d.start_time,
    d.referrer
FROM urls u
JOIN downloads d
    ON d.referrer = u.url
ORDER BY d.start_time DESC;


-- =========================================================
-- Query 5: Identify document-based payload delivery
-- =========================================================
SELECT
    id,
    target_path,
    start_time,
    mime_type,
    original_mime_type
FROM downloads
WHERE mime_type LIKE '%rtf%'
   OR original_mime_type LIKE '%rtf%'
ORDER BY start_time DESC;


/*
End of file.

These queries were used to:
- Confirm phishing URL access
- Identify malicious RTF download
- Correlate browser activity with NTFS and Sysmon timelines
*/
