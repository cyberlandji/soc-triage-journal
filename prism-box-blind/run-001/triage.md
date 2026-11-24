# Run 001 – SOC Triage
Date: 2026-11-21
Start time (run): 19:50:20
Time range used: 2026-11-21 19:50:20 → 20:45 (DONE 20:34:56 + 10 min)
Number of alerts: 10

---

## Summary
| # | Alert | Verdict | Confidence |
|---|---|---|---|
|001|Suspicious Execution via Scheduled Task|True Positive (initial) → Lab artifact / benign TP (revised after hint)|80% → 95%|
|002|Suspicious Explorer Child Process|benign TP|75%|
|003|Suspicious Explorer Child Process|Duplicate of 002 / benign TP|75%|
|004|Suspicious Explorer Child Process|True Positive (initial) → benign TP (revised after hint)|90% → 80%|
|005|Suspicious Explorer Child Process|Duplicate of 004 / benign TP|80%|
|006|Suspicious Windows PowerShell Arguments|True Positive|90%|
|007|Suspicious Explorer Child Process|benign TP|85%|
|008|Suspicious Explorer Child Process|Duplicate of 007 / benign TP|85%|
|009|Local Scheduled Task Creation|benign TP|85%|
|010|Local Scheduled Task Creation|Duplicate of 009 / benign TP|85%|

---

## Hunt
| # | Lead | Result | Report |
|---|---|---|---|
|Hunt 01|Encoded PowerShell without alert (pid 25040, 20:11)|Inconclusive (timebox)|[hunt-01_encoded-powershell](hunt-01_encoded-powershell/README.md)|
|Hunt 02|Manual 7z backup without alert (pid 25936, 20:18)|Benign · 80%|[hunt-02_7z-backup](hunt-02_7z-backup/README.md)|
