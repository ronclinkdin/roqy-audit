# roqy-audit

Read-only infrastructure audit toolkit for startups without a DevOps engineer.
Built and battle-tested by [roqy.io](https://roqy.io) on our own stack first:
every check in this repo was run against a live environment before it landed here.

roqy.io is the DevOps-as-a-service arm behind this project: one senior
engineer plus a platform, for 1-100 person startups. If you want this audit
run against your infrastructure by the people who built it:
[roqy.io](https://roqy.io).

Three layers, one report:

| Layer | Tool | What it checks |
|---|---|---|
| Repo | `skills/infra-readiness-audit` | Secrets in git, CI/CD gates, Terraform state, review gaps |
| Live | `skills/live-infra-audit` | What is actually running: ports, TLS, backups, disk, cloud, K8s |
| Change safety | [floci](https://github.com/floci-io/floci) (external) | Client IaC run against an emulated cloud before prod |

Methodology follows [Cloudflare's security-audit-skill](https://github.com/cloudflare/security-audit-skill):
recon before judgment, a pass that tries to disprove each finding, verdicts
`confirmed` / `needs_validation` / `rejected`, priority only for confirmed items.

## What it audits (full coverage)

### Docker / VPS host — `skills/live-infra-audit/references/CHECKS-VPS.md`

| # | Check | Finding if |
|---|---|---|
| L1 | Public ports | Service bound to 0.0.0.0 that should be localhost (DB, admin UI, debug port) |
| L2 | TLS | Cert expired or <14 days left |
| L3 | Restart policies | `no` on a prod container |
| L4 | Image freshness | Prod image >6 months old or unpinned `:latest` on stateful services |
| L5 | Backups | No backup cron, or output dirs empty/stale >7 days |
| L6 | Disk | Any filesystem >85% |
| L7 | Failed units | Any failed systemd service |
| L8 | Firewall | Inactive while public services listen |
| L9 | SSH | Password auth on or root password login |

### GCP — `skills/live-infra-audit/references/CHECKS-GCP.md`

| # | Check | Finding if |
|---|---|---|
| G1 | Open firewall | 0.0.0.0/0 allowing tcp:22/3389 or management ports |
| G2 | Over-privileged service account | SA with roles/editor or owner AND a user-managed key |
| G3 | VM scopes | cloud-platform scope on a running VM |
| G4 | Budget alert | Zero budgets = cloud bills with no alert |
| G5 | Disk backups | No snapshot schedule |
| G6 | Public bucket object | Anonymous 200 on an object that should be private |
| A1-A4 | Audit logs | No activity trail, no attribution, nobody watching the logs, data access unlogged (default OFF in GCP) |

### AWS — `skills/live-infra-audit/references/CHECKS-AWS.md`

| # | Check | Finding if |
|---|---|---|
| W1 | Public S3 buckets | Bucket policy public or anonymous 200 |
| W2 | Open security groups | tcp:22/3389/admin ports from 0.0.0.0/0 |
| W3 | Long-lived IAM keys | Keys older than 90 days, Active keys for departed users |
| W4 | Root MFA | Root account without MFA (P0) |
| W5 | Account-level S3 block | No account guardrail |
| W6 | CloudTrail | Zero trails = no change history |
| W7 | Budgets | None = bills with no alert |
| W8 | Config / GuardDuty | Both empty = no guardrails |
| W9 | EKS public endpoint | True without CIDR restriction. This is the EKS DEFAULT, not a misconfiguration |

### Kubernetes (GKE / EKS) — `skills/live-infra-audit/references/CHECKS-K8S.md`

| # | Check | Finding if |
|---|---|---|
| K7 | Privileged containers | Any workload pod privileged = container escape path |
| K8 | hostPath volumes | hostPath / or docker.sock = node takeover |
| K9 | RBAC over-grant | Workload service account with cluster-admin |
| K10 | Public exposure | LoadBalancer on an admin/internal panel |
| K11 | Image + limits | `:latest` images, no resource limits |
| K12 | NetworkPolicy | Zero policies = any pod reaches any pod (default on fresh clusters) |
| K13 | Token automount | Every pod holds a live API token it never uses |
| K1-K6 | Access architecture | Discovery questions: private EKS behind VPN, CI/CD path, vendor access, Jenkins with prod credentials |

### Terraform / IaC — `skills/live-infra-audit/references/CHECKS-IAC.md`

| # | Check | Finding if |
|---|---|---|
| T1 | State exists and is real | Empty state with live resources = IaC is decoration |
| T2 | Drift | Plan shows changes nobody declared = manual console changes |
| T3 | State security | State on disk unencrypted, no remote locking |

Plus the review order: static (tflint/checkov) → plan as the review artifact → state → drift → hygiene.

### Client favorites — `skills/live-infra-audit/references/CHECKS-CLIENT.md` (every audit)

| # | Check | Finding if |
|---|---|---|
| X1 | AI/LLM key sprawl | Shared company key, no spend caps. One leaked key = unlimited bill |
| X2 | Bus factor | Critical paths held by one person, no offboarding checklist |
| X3 | PII in logs | Customer data in logs with retention |
| X4 | Dependency supply chain | Lockfile untouched for months, prod on EOL runtime |
| X5 | Secrets rotation | Keys older than 90 days |
| X6 | Domain/DNS blast radius | Registrar without 2FA. A hijacked DNS beats every other finding |

## How it was validated (canary runs)

Every check was validated against a deliberately dirty throwaway environment
("canary"): plant known weaknesses, run the full audit, confirm every planted
issue is detected AND compensating controls produce `rejected`, not `confirmed`.

| Canary | Planted | Detected | Rejected correctly |
|---|---|---|---|
| GCP project | open firewall, SA editor+key, VM scope, no budget, no snapshots | 5/5 | public bucket (org policy) |
| GKE cluster | privileged pod + hostPath, LB on admin panel, cluster-admin to default SA, :latest no limits, zero netpol | 5/5 | kube-system noise (excluded by rule) |
| AWS account | public bucket with policy, open SG on 22 | 2/2 | object-ACL path (BucketOwnerEnforced) |
| AWS EKS default state | nothing — default-state findings | public endpoint, no netpol, no CloudTrail, no budgets | clean RBAC, no legacy tokens |
| roqy VPS (real) | none — real environment | 8 findings incl. 2 P0 the repo audit missed | TLS valid, restart policies ok |

Real run reports: `docs/runs/`.

## Regression harness

`harness/run_audit_harness.py` validates every run artifact: report exists,
under 120 lines, no secret/token leaks, findings.json schema, verdict hygiene
(only CONFIRMED / NEEDS_VALIDATION / REJECTED), priority only on confirmed
items, planted-finding coverage. It caught 4 real bugs across 8 live runs:

1. Priority on a needs_validation item.
2. Invented verdicts (PARTIAL, CLEAN) in headings.
3. Harness regex false positive on verdicts outside parentheses.
4. Gating on the agent process exit code instead of artifact validity.

`harness/run_scenarios.py` runs per-target scenarios (repo / vps / gcp, gke opt-in).

## Install

```bash
# Claude Code
cp -r skills/live-infra-audit ~/.claude/skills/
cp -r skills/infra-readiness-audit ~/.claude/skills/
# Cursor
cp -r skills/live-infra-audit ~/.cursor/skills/
```

Works on any [Agent Skills](https://agentskills.io) host. See
`skills/live-infra-audit/references/PORTABILITY.md` for host-specific notes.

## Run

```
run an infra readiness audit on this repo          # repo layer
audit the live server, read-only                   # live layer (confirms target first)
```

## Vulnerable lab and improvement loop

`lab/` holds a sandbox AWS lab and the loop that scores the audit against it.
The pytest suite does not call AWS.

| Path | What |
|---|---|
| `lab/vuln-lab/` | Terraform lab, read-only audit role, envelope and supply-chain plants, sample client repo, `EXPECTED-FINDINGS.yaml` (123 plants, 108 on by default) |
| `lab/lab-run/` | v3 executors (`audit_v3.py`, `audit_envelope.py`) and `checks-v3.yaml` |
| `lab/harness-loop/` | Propose, probe, compose loop: hidden grader, read-only command guard, editable overlay |

```bash
python3 -m pip install pytest pyyaml
python3 -m pytest -q lab/harness-loop/tests
```

Live probes need the read-only role from `lab/vuln-lab/access/`. Notes in the lab READMEs are in Hebrew. Coverage gaps versus the skill: `docs/aws-coverage-gaps.md`.

## Docs

- `docs/AGENT-RUNBOOK.md` — what the agent does, step by step, per client.
- `docs/CLIENT-ONBOARDING-AWS.md` — screen-by-screen: how the client creates the read-only identity.
- `docs/CONTEXT-BUDGET.md` — how the audit runs without timeouts and without blowing the agent's context window.
- `docs/runs/` — real audit reports from our own infrastructure.
- `skills/live-infra-audit/SKILL.md` — the router; loads only the reference file for the target's platform.

## License

MIT. See also [DISCLAIMER.md](DISCLAIMER.md): no warranty, read-only caveats, agent-use warnings, and the audit-not-audit clause.
