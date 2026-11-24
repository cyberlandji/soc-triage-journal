# Run 001 — Debrief

| | |
|---|---|
| Run window | 2026-11-21 19:50:20 → 20:34:56 (DONE marker) |
| Triage window | 19:50:20 – 20:45 |
| Answer key | `answer-key-run-001.md.gpg`, committed `d0c6496` before the run. The SHA-256 of the decrypted key matches `answer-key-run-001.sha256` (`8dcea291…`) |
| Debrief date | 2026-11-24 |

## 1. Results

### Alerts

| # | Alert | Key step | Ground truth | My initial verdict | Revised | Result |
|---|---|---|---|---|---|---|
| 001 | Suspicious Execution via Scheduled Task | — (LabRunner) | Lab artifact | TP 80% | Lab artifact / benign TP 95% (after hint) | ❌ Mislabel |
| 002 | Suspicious Explorer Child Process (certutil) | c3e1 | Benign | Benign TP 75% | — | ✅ |
| 003 | Suspicious Explorer Child Process (certutil) | c3e1 | Benign | Duplicate of 002, 75% | — | ✅ |
| 004 | Suspicious Explorer Child Process (Netzwerk-Check) | 9b07 | Benign | TP 90% | Benign TP 80% (after hint) | ❌ Mislabel |
| 005 | Suspicious Explorer Child Process (Netzwerk-Check) | 9b07 | Benign | Duplicate of 004, 80% | — | ✅ |
| 006 | Suspicious Windows PowerShell Arguments (fake invoice LNK) | 4f2a | **Malicious** | TP 90% | — | ✅ |
| 007 | Suspicious Explorer Child Process (backup task setup) | d0f6 | Benign | Benign TP 85% | — | ✅ |
| 008 | Suspicious Explorer Child Process (backup task setup) | d0f6 | Benign | Duplicate of 007, 85% | — | ✅ |
| 009 | Local Scheduled Task Creation | d0f6 | Benign | Benign TP 85% | — | ✅ |
| 010 | Local Scheduled Task Creation | d0f6 | Benign | Duplicate of 009, 85% | — | ✅ |

**Initial verdicts: 8/10 alerts correct.** Four of the ten alerts are Sysmon/Defend duplicates of an alert already decided, so 8/10 overstates it. **Counting independent decisions only (001, 002, 004, 006, 007, 009): 4/6 correct on the first verdict.** Both corrections (001, 004) came after a hint. The only malicious activity in the run (alert 006) was caught.

### Hunts

| Hunt | Key step | Ground truth | My verdict | Result |
|---|---|---|---|---|
| 01 Encoded PowerShell | e85d | Benign: RMM inventory via WMI (`WmiPrvSE.exe` → `powershell -EncodedCommand` → `C:\ProgramData\ITSupport\reports\inventory_*.json`) | Inconclusive (timebox) | ⚠️ Undecided. The parent `WmiPrvSE.exe` was missed. |
| 02 7z backup | 71bc | Benign: 7z backup shortcut | Benign 80% | ✅ |
| 03 API events / tmp files | — | Nothing from the generator. The `consent.exe` at 20:41:59 was my own admin PowerShell for the DONE check. | No verdict | ✅ Nothing to find |

## 2. Mislabels

### Alert 001: lab artifact called TP

- **What happened:** I treated the scheduled task + hidden PowerShell + `-ExecutionPolicy Bypass` pattern as malicious.
- **Evidence that should have changed my mind:**
  - The task name was `LabRunner`.
  - The script path was `C:\ProgramData\LabRunner\runner.ps1`.
  - Both are in the baseline record (snapshot `triage-baseline-2026-11-20 (LabRunner + seed layer)`), which documents the runner as a known component of the lab.
- **Root cause:** the category decided the verdict ("scheduled task running hidden PowerShell = bad"). I never asked *"is there a benign explanation?"*, so I didn't check the path or the baseline.

### Alert 004: benign network check called TP 90%

- **What happened:** a user-launched shortcut that started a scripting process looked like the same pattern as a phishing LNK.
- **Evidence that should have changed my mind:** what the command actually did (a network check), and no follow-on activity (no child processes, no persistence, no staging, no outbound traffic beyond the check).
- **Root cause:** the same as alert 001. The benign hypothesis was missing, and the high confidence (90%) wasn't backed by checking what the process did.

### Hunt 01: undecided

- **Missed:** the parent process `WmiPrvSE.exe`. That points to a WMI-launched management tool, which is a typical RMM/inventory pattern.
- **What I got right:** my analysis of why the rule didn't fire was correct. The long form `-EncodedCommand` only matches in the last OR branch, and that branch requires parent `explorer.exe` or `cmd.exe`. With `WmiPrvSE.exe` as the parent, there was no alert, by design of the rule.
- **Lesson for next time:** decode first, then check the parent and the output path. Here the decoded content plus the `ITSupport\reports` path would have settled it.

## 3. The malicious chain (4f2a): why only the first stage ran

**Planned chain (from the key):**
1. Fake invoice LNK
2. Hidden PowerShell `-enc`
3. IEX of `theme.dat`
4. Discovery
5. HKCU Run `ThemeSync`
6. Credential collection
7. `upd_cache.zip` staging
8. DNS + HTTP POST C2
9. Cleanup

**What happened:**
- Microsoft Defender detected the command line about 0.5 seconds after the PowerShell started (`ClickFix.ZB`, most likely through AMSI) and blocked it before the IEX payload ran.
- There is no 4104 script-block event for the payload.
- Four independent checks came back empty:

| Check | Query focus | Result |
|---|---|---|
| Children of the PowerShell | `process.parent.pid : 3696` | Empty |
| Persistence | Registry `ThemeSync` | Empty |
| Staging / discovery files | `upd_cache.zip`, `~DF4A21.tmp`, `svcupd.ps1` (+ `*zip*`) | Empty |
| C2 | DNS `cdn-update`, port 8443 | Empty |

**Conclusion:** stages 3–9 never ran. My scoping after alert 006 found nothing because there was nothing to find. The verdict stays **TP**: in real life "blocked by AV" is still a true positive, and the response is to verify containment (persistence absent ✓; the `.lnk` and `theme.dat` would still need removing).

Caveat: missing logs are not perfect proof. Four independent checks plus the Defender event make it a strong conclusion, not a certainty.

### Decision: no replay with a Defender exclusion

The lab could add a Defender exclusion so the full chain runs and tests Elastic's own detections. **I keep the run as it is.** The goal of this lab is triage under realistic conditions, and in reality the AV stopped a commodity payload. What matters is that the malicious activity was caught and correctly labelled.

### Note for anyone running the LabRunner themselves

> The generator was designed without accounting for Microsoft Defender's
> real-time protection and AMSI. On a default Windows 10 with Defender
> enabled, the malicious scenario in run 001 is blocked at the first
> PowerShell stage, so the later stages (discovery, persistence,
> credential collection, staging, C2) do not produce telemetry. This is
> a lab-design limitation, not a bug in the triage. If you want the full
> chain to run, you would need a lab-only Defender exclusion. That
> changes the test from "does the defence stop it?" to "does the SIEM
> see it?".
>
> The runner (`runner.ps1`) is not published, but I can share it on request.

## 4. Correction to the answer key

The key describes `7z.exe` as signed. The telemetry showed `code_signature.exists: false`. **The telemetry wins.** This was an error in the key, not in my hunt 02 analysis.

## 5. Confirmed detection gaps

| # | Gap | Impact |
|---|---|---|
| G1 | Microsoft Defender 1116/1117 events did not create an alert in Kibana | The only real detection of the attack was invisible in the SIEM alert queue |
| G2 | 4688-only visibility for the alert 006 PowerShell | Windows Security 4688 has no `entity_id`, no parent args and no `original_file_name`. The Explorer Child rule couldn't see it, and the Analyzer can't build the tree. |
| G3 | No Elastic Defend / Sysmon process event for pid 3696 | Unexplained. To investigate (possibly the Defender block happened before the sensors recorded the start). |

## 6. Tuning candidates

| ID | Candidate | Note |
|---|---|---|
| T1 | Narrow exception for the LabRunner (exact task name + script path + hash) | Must not exclude hidden PowerShell in general |
| T2 | Explorer `/factory` CLSID `{75dff2b7-6936-4c06-a8bb-676a7b00b24b}` | ⚠️ The malicious PowerShell in alert 006 used the same `/factory` handoff. Research the CLSID before excluding anything. |
| T3 | Alert suppression for the 4 Sysmon/Defend duplicate pairs (002/003, 004/005, 007/008, 009/010) | Suppress duplicates; don't disable a data source |
| G1 fix | Prebuilt rule or alert for Defender 1116/1117 | Follow the detection gate: prebuilt first, custom only if nothing fits |

## 7. Security+ (SY0-701) links

| Topic in this run | Domain |
|---|---|
| Fake invoice LNK lure (social engineering), encoded PowerShell, LOLBins (certutil, schtasks) | 2.2 Threat vectors / 2.4 Indicators of malicious activity |
| AV/EDR blocking a payload, EDR vs SIEM visibility | 4.5 Enterprise capabilities to modify security |
| Alert tuning, false positives, duplicate alerts, baselines | 4.4 Alerting and monitoring |
| Triage, scoping, containment check after a blocked attack | 4.8 Incident response |
| Sysmon vs Defend vs 4688 vs PowerShell logs | 4.9 Data sources to support an investigation |

## 8. Lessons (in my own words)

- Triage is not something trivial as I thought. A lot of work should be done in order to decide if an alert is TP (True Positive) or FP (False Positive).
- TP is not only malicious, there is a benign TP too, and it is important to distinguish both.
- When reviewing an alert, I learnt that the most important question to ask myself was: "What makes this event benign?" If we can defend it with true evidence and with the context, then the alert could be a benign TP.
- Each field has its importance during the investigation. We can have fields like `process.name` and `event.category`, which are standard fields to have in Discover, but to properly define the context and scope, we need to use other relevant fields as queries and sometimes combine them together.

