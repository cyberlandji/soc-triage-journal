## Alert 1: Suspicious Execution via Scheduled Task
- **Alert Time:** 19:52:27.237
- **Event Time / host / user:** 19:50:09.720 /desktop-eb94l4c/pb##
- **Severity / risk score:**: Medium / 47
- **What fired:** Suspicious Execution via Schedlued Task by looking at the process lineage and command line usage )
- **Process tree:** svchost.exe → process → powershell.exe (Analyzer)
- **What I checked:** (queries: host.name : "desktop-eb94l4c, fields: process.command_line; process.name; process.parent.name; event.code, enrichment like VirusTotal/AbuseIPDB)
- **Benign hypothesis:** what would make this harmless? Evidence for/against:A scheduled task is something that commonly happen, it would be harmless if the process command line were not ambiguous. the fact that >
- **Verdict:** TP · confidence 80 %
- **Reasoning:** I have look at the process.command_line and look into args and see if anything were ok, then look into the the file which were executed to see if it is now from our view. the correlation of both >
- **Follow-up / tuning idea:**Since the rule catch this event, I have no tuning idea for this event

---

## Hunt (15 min)
| Query | What I looked for | Finding |
|---|---|---|

## Summary
| # | Alert | Verdict | Confidence |
|---|---|---|---|
|001|Suspicious Execution via Scheduled Task| True Positive | 80% |
