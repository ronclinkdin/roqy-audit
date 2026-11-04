# Validation and reporting

## Verdicts (closed set)

`confirmed`, `needs_validation`, `rejected`. No other words exist. `partial`, `clean`, `ok`, `warning` are forbidden in headings and findings. If you cannot classify, the verdict is `needs_validation`. Agents left free will invent verdict words; the regression harness rejects them, so never write them.

## Verify pass

Before anything enters the report: re-run the command, confirm the evidence is current, look for a compensating control (reverse proxy in front, firewall elsewhere, org policy, another repo, a SaaS tool). A checklist deviation with no concrete consequence is a note, not a finding.

## Priorities (confirmed items only)

- **P0:** public admin/DB port, expired TLS on the main domain, no backups of customer data, disk >95%, public bucket with customer data.
- **P1:** no restart policy on prod container, stale backups, disk >85%, password SSH auth, no firewall, no budget alert, no CloudTrail.
- **P2:** stale images, dead containers, pending reboot, lab containers with `no` restart policy, missing account guardrails.

Rule of thumb: if you cannot say what concretely breaks, lower the priority.

## Report format

File: `live.md` in `~/infra-readiness-audit/<target>/<date>/`. Heading format is strict:

`### <id> — <title> (CONFIRMED, P0)`

Verdict is exactly CONFIRMED, NEEDS_VALIDATION, or REJECTED. Sections that could not run get a line `not_applicable: <reason>`, never silence and never a new verdict word.

Contents: inventory table, findings with exact redacted command output as evidence, consequence, smallest fix, effort, and an execution order that groups changes sharing one change window (e.g. firewall rules together). Under one page per 10 findings, hard cap 120 lines.

findings.json (when produced): one object per item with id, category, title, status, priority, evidence, consequence, fix, effort. Priority ONLY on confirmed items — the harness fails a run that puts priority on needs_validation.

## Harness

Validator: /root/roqy-audit/harness/run_audit_harness.py (`validate <dir>` checks report exists, under 120 lines, no secret/token leaks, findings.json schema, verdict hygiene, planted-finding coverage, per-family keyword coverage as WARN for old reports). Scenario runner: /root/roqy-audit/harness/run_scenarios.py (repo / vps / gcp, gke opt-in). `live` mode runs the skill end-to-end via `hermes chat -s live-infra-audit --yolo` against the canary and validates the output.

Run the harness after every skill change. It caught a priority-on-needs_validation violation and an invented-verdict heading on its first passes. Gate on artifact validation, not on the hermes process exit code: max-turns exhaustion after the report is written still counts as success. Keep the repo copy and the profile copy of the skill in sync (cp after every edit).

## Harness lessons (real catches)

- priority on a needs_validation item (F5) — fixed in findings.json.
- invented verdicts PARTIAL and CLEAN in headings — fixed by strict heading format in the skill + verdict constraint in the live prompt.
- harness regex false positive on verdicts outside parentheses — fixed by scanning the whole heading line.
- hermes exit 1 after writing a valid report — gate on artifacts, not exit codes.


## The fear layer (every P0/P1 finding tells the story)

A finding is a fact. A danger is a story. People act on stories. Every P0 and P1 finding in the report carries a three-sentence chain after the evidence:

1. How the attacker gets in (the exact vector, in their words: "one anonymous GET").
2. What they do next (the escalation: "mint a key, list S3, copy the state file").
3. What it costs (money, downtime, or a named precedent: "this is the Capital One vector, 100M records").

Rules:

- The chain must be specific to THIS finding, not a generic scare paragraph. Name the actual resources from the report.
- Use a real precedent only when it genuinely matches the vector. One accurate precedent beats three approximate ones.
- P2 findings get one sentence at most. Fear inflation on small findings destroys trust in the big ones.
- Never invent numbers. Cost estimates are ranges with the assumption stated ("if the bucket holds backups: restore cost plus breach notification").
- The closing line of the report is the one-sentence version: what happens if nothing is fixed, in plain words.

Example (real finding from the AWS canary):

> F2: bucket readable and writable by anyone (CONFIRMED, P0). One anonymous request lists and overwrites every object. An attacker plants a poisoned artifact or wipes the backups, and the restore you thought you had is gone. This is the PREMINT 2022 vector: one open bucket, NFT theft at scale.
