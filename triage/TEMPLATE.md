# Tier 1 Triage Template

Use one copy per alert. Fill every `TODO` from **observed** evidence only. Never invent firings or outcomes.

| Field | Value |
|-------|-------|
| Alert / rule name | TODO |
| Detection file | `detections/TODO.kql` |
| Time generated (endpoint / Sentinel) | TODO |
| Host (placeholder if public) | TODO e.g. `PC-01` |
| User (placeholder if public) | TODO e.g. `CONTOSO\user01` |
| Severity (rule) | TODO |
| MITRE ATT&CK | TODO |

## What fired

- TODO: Summarize the triggering fields (Image, CommandLine, TargetObject, DestinationIp, GrantedAccess, etc.).
- TODO: Paste **redacted** key EventData snippets only (run `Invoke-SysmonRedact.ps1` first if exporting).

## How verified

- TODO: Parent/child process chain checked? (yes/no + notes)
- TODO: Signed / expected path? Reputation / hash lookup done privately?
- TODO: Related Sysmon EIDs reviewed (1 / 3 / 10 / 11 / 13 / …)?
- TODO: User or change ticket context (maintenance window)?

## Decision

- [ ] **Close** — false positive / expected activity  
- [ ] **Monitor** — weak signal; document and watch  
- [ ] **Escalate** — likely malicious or needs Tier 2 / IR  

Rationale: TODO

## Ticket note (paste-ready)

```
TODO — one short paragraph suitable for a ticket: what, where, why this decision, next owner.
```

## Follow-ups

- TODO: Detection tuning needed? Allowlist candidate?
- TODO: Containment or password reset requested? (only if evidence supports it)

---
Analyst: TODO  
Date (UTC): TODO  
