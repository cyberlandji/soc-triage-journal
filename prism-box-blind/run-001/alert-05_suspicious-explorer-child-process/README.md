## Alert 5: Suspicious Explorer Child Process
- **Alerttime:** 20:02:02.203
- **Time / host / user:** 19:57:44.054 / desktop-eb94l4c / pb-victim
- **Severity / risk score:** Medium / 47
- **What fired:** Identifies a suspicious Windows explorer child process. Explorer.exe can be abused to launch malicious scripts or executables from a trusted parent process.
- **Process tree:** parent: explorer.exe child: cmd.exe then cmd.exe is parent with ping.exe, ipconfig.exe, nslookup.exe and netstat.exe as his children
- **What I checked:** queries: host.name; data_stream.dataset; fields: process.parent.args, process.args, process.command_line, process.parent.name, event.action, process.name
- **Benign hypothesis:** what would make this harmless? Evidence for/against:the process tree explorer.exe (parent) -> cmd.exe (child) is commonly used in allday. Plus the commands used in children process of cmd.exe are recon commands who seems to be harmful in this context.
- **Verdict:** benign-TP · confidence 80%
- **Reasoning:**The process.args contain (ipconfig, nslookup, netstat, ping) which are well-known recon commands. Those commands can be used by IT service (Net administrator, IT Support) and by malicious actor too, both are true, so we need to enlarge the context. those commands were saved in a netcheck.txt file and this file was not further used (only one entry /event (creation)  when using the query file.name : "netcheck.txt") Adding to this the creation and performing of a shortcut Netzwerk-Check.lnk seconds before the commands were ran, the context seems benign. 
- **Follow-up / tuning idea:** This alert is a duplicate from alert 4, but with another sensor/data_stream.dataset (this time EDR/endpoint.process.event instead of Sysmon/windows.sysmon_operational)
  - Same process: same timestamp (19:57:44.054), same process.pid (8324) and process.parent.pid (25596); only process.entity_id differs (EDR `daCAZ7xR6WNxUm9za+4Wsg`, Sysmon `{11E61AE5-E9A8-6B01-8603-000000001D00}`).
  - Windows Security log 4688 recorded the start too but cannot alert on this rule (no process.parent.args). Same blind spot as alerts 2/3.
  - Tuning (T3): +1 duplicate pair.

---

## Hunt (15 min)
| Query | What I looked for | Finding |
|---|---|---|

## Summary
| # | Alert | Verdict | Confidence |
|---|---|---|---|
|005|Suspicious Explorer Child Process|benign TP|80%|
