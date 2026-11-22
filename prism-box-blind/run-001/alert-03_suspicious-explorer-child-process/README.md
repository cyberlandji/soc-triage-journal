## Alert 3: Suspicious Explorer Child Process
- **Alert time:** 19:57.02.131
- **Time / host / user:** 19:52:34 / desktop-eb94l4c / pb-victim
- **Severity / risk score:** Medium / 47
- **What fired:** Identifies a suspicious Windows explorer child process. Explorer.exe can be abused to launch malicious scripts or executables from a trusted parent process
- **Process tree:** parent: explorer.exe→ process → children (Analyzer)
- **What I checked:** (queries:host.name : "desktop-eb94l4c", fields: process.name; event.action; process.command_line; process.parent.name; winlog.task; file.path; file.name, process.parent.args
- **Benign hypothesis:** what would make this harmless? Evidence for/against:
- **Verdict:** benign-TP · confidence 75%
- **Reasoning:** Duplicate of alert 2, no separate analysis. Same verdict as alert 2.
- **Follow-up / tuning idea:** This alert is a duplicate from alert 2, but with another sensor/data_stream.dataset (this time EDR/endpoint.process.event instead of Sysmon/windows.sysmon_operational)
  - Same process: same timestamp (19:52:34.524), same process.pid (4992) and process.parent.pid (29616); only process.entity_id differs because each sensor uses its own ID format (Sysmon `{11E61AE5-E872-6B01-7103-000000001D00}`, EDR `6fYkvvTWkSF9Uoe111ckPQ`).
  - The same process start was also recorded by the Windows Security log (system.security, 4688), but it did not alert: 4688 does not record process.parent.args, and the rule needs process.parent.args : "-Embedding". Blind spot on 4688 alone, which is why it is good to have more sources and not rely on just one.
  - Tuning (T3): count duplicates first, then decide. Do not disable a data source; tune the alert (e.g. alert suppression), not the telemetry.

---

## Hunt (15 min)
| Query | What I looked for | Finding |
|---|---|---|

## Summary
| # | Alert | Verdict | Confidence |
|---|---|---|---|
|003|Suspicious Explorer Child process|benign TP |75% |
