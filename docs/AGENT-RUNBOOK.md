# Agent Runbook — roqy-audit

What the agent does for one client audit, end to end. Read-only unless the
client explicitly approves a fix.

## 0. Intake (5 min, chat)

Ask three questions, nothing more:

1. Where does prod run? (VPS / Docker / AWS / GCP / mix)
2. Repo URL or local path?
3. For cloud: is there a read-only identity? If not, send `CLIENT-ONBOARDING-AWS.md`.

## 1. Repo layer (30-60 min)

Run `infra-readiness-audit` full audit mode:

- Phase 1 recon: inventory.md first. No judgment yet.
- Phase 2 checks: static only. No live cloud calls without approval.
- Phase 3 verify: second pass that tries to disprove each finding.
- Phase 4: REPORT.md + findings.json in `~/infra-readiness-audit/<repo>/<date>/`.

## 2. Live layer (30 min)

Run `live-infra-audit`:

- Confirm the target host with the client in one message before the first command.
- Inventory first (containers, ports, disk, cron), then the L1-L10 checks.
- Cloud target: only after `aws sts get-caller-identity` output is shown to the client and they say yes.

## 3. Report delivery (10 min)

One page to the client:

- Findings table: id, priority, one-line consequence, fix, effort.
- P0 items highlighted. Total estimated effort.
- Offer: "we can fix the P0s now" (this is where the retainer starts).

## 4. Change safety (per client with IaC)

- If the client has Terraform/CloudFormation: floci in their CI, changes validated against an emulated cloud before prod.
- Never apply anything from the audit ourselves without a written go.

## Rules that never bend

- Read-only. Evidence for every finding. Secrets redacted to 4 chars.
- A checklist deviation with no concrete consequence is a note, not a finding.
- Say what was not checked. Never claim full coverage.
