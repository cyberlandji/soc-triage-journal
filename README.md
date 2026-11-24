# SOC Triage Journal

Blind L1 alert triage practice. I make TP/FP verdicts with documented reasoning, without knowing what was simulated, then debrief them against ground truth that was locked before the run.

This is a self-directed home lab, not professional SOC experience. All verdicts, including the wrong ones, are published as they were made.

## Runs

| Run | Answer key sealed | Run | Alerts | First-verdict accuracy (independent decisions) | Malicious activity | Debrief |
|-----|-------------------|-----|--------|-----------------------------------------------|--------------------|---------|
| [Run 001](prism-box-blind/run-001/) | 2026-11-20 (`d0c6496`) | 2026-11-21 | 10 + 3 hunts | 4/6 | Caught and scoped | [debrief.md](prism-box-blind/run-001/debrief.md) |

*Accuracy counts independent decisions: duplicate alerts for the same event are counted once. On all 10 alerts the raw figure is 8/10, which overstates it. The answer key is always sealed before the run, which is why the two dates differ.*

## How the blind setup works

- **Lab:** self-hosted Elastic Stack (SIEM, Fleet) with a Windows 10 endpoint running Elastic Defend, Sysmon, Windows Security auditing, PowerShell logging and Microsoft Defender, about 550 prebuilt detection rules enabled after a documented baseline. The infrastructure comes from my [Prism Box](https://github.com/cyberlandji/prism-box) project.
- **Generator:** a scheduled PowerShell runner executes a run plan that mixes benign admin activity with one or more simulated attack chains. The only timing information I get is a completion marker. The generator was built with AI assistance (Claude), and I don't read the run plans, so the triage stays blind. Generator source and run plans stay private so future runs stay blind.
- **Cycle:** generate (blind) → triage → hunt → debrief → gap analysis → tune → replay.

## How you can check the verdicts weren't changed afterwards

1. **Before each run** the answer key is GPG-encrypted and committed together with the SHA-256 hash of its plaintext.
2. **During triage** reports and screenshots are committed in small batches (one or two alerts per commit), before the debrief.
3. **After the debrief** the plaintext answer key is published.

To verify a run yourself:

```bash
git log --format='%h %ad %s' --date=iso -- prism-box-blind/run-001/
# the sealed-key commit (d0c6496) must be older than the report commits

cd prism-box-blind/run-001/
sha256sum -c answer-key-run-001.sha256
# must print: answer-key-run-001.md: OK
```

If I revise a verdict after a hint, the revision is kept next to the original and marked "after hint". The original is never edited.

## What each run contains

- `triage.md`: summary of all verdicts and hunts, with confidence levels; verdicts revised after a hint are marked as such
- One folder per alert: alert summary, evidence (queries and screenshots), verdict and reasoning. From run 002, each report starts with a benign hypothesis.
- Hunts for activity that raised no alert (15-minute timebox each)
- Debrief: verdicts compared with the answer key, root cause of each mislabel, detection coverage gaps, tuning candidates

## Repository layout

- `prism-box-blind/baseline/`: enabled detection rules at the documented baseline, and my public GPG key
- `prism-box-blind/run-NNN/`: one folder per run (alerts, hunts, triage summary, sealed answer key, debrief)

## Not published

Server addresses, credentials, generator source, run plans for future runs, and any finding that hasn't been fixed yet.

## Contact

Questions, or interested in the runner (`runner.ps1`)? Reach me on [LinkedIn](https://www.linkedin.com/in/yohan-cedric-landji).
