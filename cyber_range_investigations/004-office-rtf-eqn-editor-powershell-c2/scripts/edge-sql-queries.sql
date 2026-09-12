/*
Case ID: 004
Case Name: Office RTF (Equation Editor) → PowerShell Persistence → C2
Source Platform: CyberDefenders CyberRange
Purpose: Exact record of the Microsoft Edge queries preserved in the
         surviving analyst notes for this investigation
Time Standard: UTC (unless CyberRange explicitly states otherwise)

NOTE:
- Both statements below are reproduced as recorded in the analyst notes
- No other query is preserved in the surviving record for this case
- Queries are read-only
*/

-- =========================================================
-- Query preserved in the notes: non-HTTPS URLs (Q1)
-- =========================================================
SELECT * FROM urls
WHERE url LIKE '%http%'
AND url NOT LIKE '%https%';


-- =========================================================
-- Query preserved in the notes: download records (Q2)
-- =========================================================
select * from downloads

