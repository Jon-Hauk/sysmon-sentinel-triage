# Sysmon → Sentinel Triage

Sysmon detections and Tier 1 triage templates for Microsoft Sentinel: KQL queries over the `Event` table, a triage write-up for each, and a redaction script for sharing sample events safely.

> **Status:** Draft. Every detection is tested against synthetic events on a real Kusto engine, but none has run against live Sysmon telemetry yet, so field extraction and false-positive rates are unproven. Triage notes are stubs with `TODO` fields. No live alert results are claimed here.

## Purpose

1. Collect process, network and registry events with Sysmon.
2. Ship them through Azure Monitor Agent (AMA) and a Data Collection Rule (DCR).
3. Hunt and alert with KQL analytics rules in Microsoft Sentinel.
4. Document Tier 1 triage without publishing real endpoint data.

## Architecture

```
Windows endpoint (Sysmon)
        │
        ▼
Azure Monitor Agent + Data Collection Rule (DCR)
        │
        ▼
Log Analytics workspace  (Event table, Source == Microsoft-Windows-Sysmon)
        │
        ▼
Microsoft Sentinel analytics rules (KQL in detections/)
        │
        ▼
Tier 1 triage notes (triage/), filled from real alerts privately
```

Secrets and Azure resource IDs are **never** stored in this repo.

## Detections

| File | Sysmon EID | ATT&CK (primary) | Severity |
|------|------------|------------------|----------|
| `detections/encoded-powershell.kql` | 1 | T1059.001 | Medium |
| `detections/lolbin-download.kql` | 1 | T1105 | High |
| `detections/lsass-access.kql` | 10 | T1003.001 | High |
| `detections/persistence-run-key.kql` | 13 | T1547.001 | Medium |
| `detections/process-user-writable-path.kql` | 1 | T1036 / T1204.002 | Low-Medium |
| `detections/script-host-outbound.kql` | 3 | T1059 / T1071 | Medium |

Check field extraction against your own workspace before enabling a rule.

## Tests

Both run on Windows PowerShell 5.1.

```powershell
.\tests\Test-Detections.ps1   # synthetic events through each query, on Microsoft's public Log Analytics demo workspace
.\tests\Test-Redactor.ps1     # offline: fake CSV and JSON exports, including every refusal path
```

The detection tests prove query logic against hand-written events, including events each query must not match. They say nothing about a live workspace's schema or real-world noise.

## Privacy

- **Real Sysmon logs stay private.** Do not commit `.evtx`, `raw/`, `exports/`, or unredacted CSV/JSON.
- Public samples under `samples/` are **synthetic** and labelled as such.
- Placeholders used in docs and samples: `PC-01`, `user01`, `contoso.onmicrosoft.com`, `192.0.2.x` (TEST-NET-1), documentation MAC addresses (`00-00-5E-00-53-xx`).
- Before sharing any exported events, run `scripts/Invoke-SysmonRedact.ps1`, then read the output. It refuses to write if anything it recognises survives, but free text can hold things no rule knows about, such as a password typed into a command line.

## Licensing

| Content | Licence |
|---------|---------|
| KQL queries, scripts, tests and synthetic samples | [Apache-2.0](LICENSE) |
| Documentation (README, triage templates) | [CC-BY-4.0](LICENSE-docs) |

This repo ships no Sysmon configuration. If you adopt a community one (for example [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) or [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular)), **check that project's licence**, credit the authors, and do not re-license their XML as Apache-2.0.

## Cost

Neither Log Analytics nor Microsoft Sentinel is free by default. Microsoft has offered a time-limited Sentinel trial and a monthly Log Analytics free allowance on eligible workspaces. Check current pricing and regional limits before enabling Sentinel or raising retention, and set a budget alert first.

## Setup (high level)

1. Run Sysmon on a Windows endpoint you own, with a config you chose and credited.
2. Create or reuse a Log Analytics workspace; enable Microsoft Sentinel if wanted.
3. Install Azure Monitor Agent and associate a DCR that collects the Sysmon channel.
4. Confirm events land in the `Event` table with `Source == "Microsoft-Windows-Sysmon"`.
5. Paste queries from `detections/*.kql` into Logs, fix any field extraction that does not match, tune false positives, then create analytics rules.
6. When an alert fires, copy the matching stub from `triage/` and fill every `TODO` from **observed** evidence only.
7. Redact anything you might share with `scripts/Invoke-SysmonRedact.ps1`.

## Repository layout

```
detections/     KQL detection templates (Sysmon Event table)
triage/         TEMPLATE.md + one stub per detection
scripts/        Invoke-SysmonRedact.ps1
samples/        Synthetic events only
tests/          Detection and redactor tests
```

## AI disclosure

This repository was **built with AI coding assistance**, and AI output may contain mistakes. The tests in `tests/` are the evidence for what has been checked. Treat everything else, including how the queries behave on live data, as unverified.

## Disclaimer

Educational use on systems you own or are authorized to monitor. No warranty. Not a substitute for a production detection engineering program.
