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
