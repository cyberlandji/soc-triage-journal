# Answer key — Prism Box blind triage, run-001

Baseline: `triage-baseline-2026-11-20` (LabRunner + seeding layer installed; 550 rules, see `enabled-rules-2026-11-19.csv`).
Map runner log `C:\ProgramData\LabRunner\logs\run-001.log` (UTC timestamps, `step=<id> ok`) to the steps below.
Alert names listed under "likely alerts" are expectations, not guarantees — the debrief uses what actually fired.

## Summary

| Step | Label | What it is | Launch (parent) |
|---|---|---|---|
| c3e1 | **Benign** (FP bait) | User verifies downloaded installers with `certutil -hashfile` | explorer.exe → cmd.exe → certutil.exe |
| 9b07 | **Benign** (FP bait) | User's own "Netzwerk-Check" desktop shortcut: ipconfig / ping / nslookup / netstat | explorer.exe → cmd.exe |
| 4f2a | **MALICIOUS** (TP) | Fake invoice LNK → hidden encoded PowerShell → discovery → Run-key persistence → credential collection → archive → C2/exfil attempt → cleanup | explorer.exe → powershell.exe (-enc, hidden) |
| e85d | **Benign** (FP bait) | RMM-style IT inventory via WMI: encoded PowerShell writes disk/hotfix JSON to `C:\ProgramData\ITSupport\reports` | WmiPrvSE.exe → powershell.exe (-EncodedCommand) |
| 71bc | **Benign** (FP bait) | User's "Backup Dokumente" shortcut: 7-Zip archives Documents to Desktop | explorer.exe → 7z.exe |
| d0f6 | **Benign** (FP bait) | User schedules a weekly 7-Zip backup task (`schtasks /create`, 4698) | explorer.exe → cmd.exe → schtasks.exe |

**Ground truth: 1 malicious chain, 5 benign activities.** Everything except 4f2a must be closed as FP / benign-true-positive.

## 4f2a — the malicious chain (detail)

| Stage | ATT&CK | Activity | Evidence to look for |
|---|---|---|---|
| Delivery / execution | T1204.002, T1059.001, T1027 | `Downloads\Rechnung_2026-11.pdf.lnk` (PDF icon, double extension) runs `powershell.exe -nop -w hidden -ep bypass -enc …` | parent explorer.exe; hidden window; `-enc` decodes to `IEX ([IO.File]::ReadAllText("$env:APPDATA\Microsoft\Windows\Themes\theme.dat"))`; 4104 shows full payload |
| Discovery | T1033, T1087.001, T1069.001, T1082, T1016, T1057, T1049 | whoami /all, net user, net localgroup administrators, systeminfo, ipconfig /all, tasklist /v, netstat -ano → `%TEMP%\~DF4A21.tmp` | burst of discovery children of one hidden powershell |
| Persistence (+2–4 min) | T1547.001 | HKCU Run value `ThemeSync` → `powershell.exe -nop -w hidden -ep bypass -file %APPDATA%\Microsoft\Windows\Themes\svcupd.ps1` | registry event by the same powershell PID |
| Credential access / collection (+2–4 min) | T1555.004, T1552.001, T1555.003, T1005 | `cmdkey /list`; `findstr /s /i /m password Documents\*.txt`; copies `.aws\credentials`, `.ssh\id_ed25519`, FileZilla `sitemanager.xml`, Edge/Chrome `Login Data`, Firefox `logins.json` into `%TEMP%\c41` | file reads of browser credential stores by powershell (non-browser) |
| Staging (+1.5–3 min) | T1560.001 / T1074.001 | `Compress-Archive` → `%TEMP%\upd_cache.zip` | zip created by the same powershell |
| C2 / exfil attempt | T1071.001, T1041 | DNS query `sync.cdn-update.invalid` (NXDOMAIN); HTTP POST `http://10.10.10.1:8443/api/v2/sync` (refused) | DNS + network events from powershell; non-standard port |
| Cleanup | T1070.004 | `%TEMP%\c41` deleted | file deletions |

**Scoping answer:** one host (desktop-eb94l4c), one user (pb-victim), one process lineage (the hidden powershell from the LNK). Persistence = Run key `ThemeSync`. Exposed (fake) secrets: Credential Manager entries, AWS keys, SSH key, FileZilla creds, browser stores, password hits in Documents. Exfil failed (no listener) but **intent and staging are confirmed**. Recommended response: isolate host, remove Run key + `Themes\theme.dat`/`svcupd.ps1`/LNK, rotate all listed credentials, block destination, hunt for the LNK delivery path.

## Benign steps — why they are FP

| Step | Looks like | Why it's benign | Evidence that should change your mind |
|---|---|---|---|
| c3e1 | certutil LOLBin use (T1105/T1140 style alerts) | `-hashfile … SHA256` only computes a hash of local installers; no `-urlcache`, `-decode`, no network | command line; output `Downloads\hash_check.txt`; files hashed = 7-Zip / Notepad++ installers the user downloaded |
| 9b07 | network discovery burst | user-initiated from a named desktop shortcut, visible console, output to `Desktop\netcheck.txt`; no follow-on activity | parent explorer, single short-lived cmd, nothing after |
| e85d | encoded PowerShell via WMI (lateral-movement / execution pattern) | decodes to read-only inventory (Win32_LogicalDisk, Get-HotFix, LastBootUpTime) written to an IT folder; no network, no persistence | **decode the -EncodedCommand**; output path `C:\ProgramData\ITSupport\reports\inventory_*.json` |
| 71bc | archive of user documents (T1560 collection/staging) | user shortcut, archive stays on the user's Desktop, real 7-Zip binary, no exfil after | parent explorer → 7z.exe (signed), destination Desktop, no network |
| d0f6 | scheduled-task persistence (4698, T1053.005) | task runs signed 7z.exe weekly to back up Documents to Desktop; created interactively, readable name, not hidden, not deleted | task action content; creator cmd from explorer; no encoded/obfuscated args |

## Known lab artifacts (not evidence)

LabRunner scheduled task, `C:\ProgramData\LabRunner\*` (runner.ps1, packs, logs, `l\*.lnk`), and file writes by the runner powershell (parent svchost/Schedule). The runner also *places* the delivery files (LNK, theme.dat) — in reality those would arrive via browser/mail.

## Debrief checklist

- [ ] Verdict per alert vs this key; list every mislabel (FP↔TP)
- [ ] Did the hunt find chain stages that did **not** alert?
- [ ] Gap analysis for every silent TP stage (telemetry? rule disabled? logic? no rule?)
- [ ] Tuning candidates for noisy benign alerts (exceptions, not rule deletion)
