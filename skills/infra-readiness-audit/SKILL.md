---
name: infra-readiness-audit
description: Read-only infrastructure readiness audit for small engineering teams with no dedicated DevOps/platform engineer. Reviews a repository plus its Terraform, Kubernetes, CI/CD (GitHub Actions) and, if the user allows, live AWS or GCP read-only state, then writes a prioritized report. Use when asked to "audit our infra", "what should we fix before our first DevOps hire", "check our cloud setup", "pre-hire infra review", or for focused questions about IAM, Terraform state/drift, secrets in code, deploy gates, alerting, backups/DR, cloud cost alerts, PR review gaps, or visibility into production changes.
---

# Infra Readiness Audit

Find the infrastructure gaps that will hurt a small team first: who can do what in the cloud, whether the code still describes reality, where secrets live, how changes reach production, whether anyone notices when it breaks, and whether you can recover. Every finding needs evidence and a concrete consequence. A missing best practice with no consequence is a note, not a finding.

This skill only reads. It never changes code, cloud resources, cluster objects, CI settings, or state.

## Operating modes

- **Guidance mode (default).** For a focused question ("are our GitHub Actions safe?"), use only the relevant section of `CHECKS.md` and answer in the conversation. Do not create files.
- **Full audit mode.** When the user asks for a full audit, a readiness review, or a report, run all phases below and write the report files.

If unclear, ask one question before starting a full audit.

## Hard safety rules (both modes)

1. **Read-only, always.** Run only commands that list, describe, get, or read. Never run: `terraform apply|destroy|import|state rm|state mv|state push|force-unlock|refresh`, `kubectl apply|delete|edit|patch|scale|rollout restart|exec|cp`, `helm install|upgrade|uninstall|rollback`, any `aws ... create-*|put-*|update-*|delete-*|attach-*|detach-*`, any `gcloud ... create|update|delete|add-iam-policy-binding|remove-iam-policy-binding|set-iam-policy`, or `gh` commands that edit, merge, close, or change settings.
2. **Ask before touching live accounts.** Static repo review needs no permission beyond the repo. Before the first live cloud or cluster command, show the user the identity and target (`aws sts get-caller-identity`, `gcloud config list`, `kubectl config current-context`) and get an explicit yes. Prefer a read-only role (AWS `ReadOnlyAccess` or `SecurityAudit`; GCP `roles/viewer` plus `roles/iam.securityReviewer`). If the current identity is an admin, say so and ask whether to continue.
3. **Never print secret values.** Report the file, line, and secret type, and redact the value (show at most the first 4 characters). Do not read Kubernetes Secret data (`kubectl get secret -o yaml/json`), Secret Manager versions, SSM SecureString values, or `.env` contents beyond key names. Do not try a found credential to see if it is live.
4. **No probing.** Do not send traffic to production endpoints, do not run load or availability tests, and do not trigger workflows or deploys.
5. **Mind paid calls.** AWS Cost Explorer API calls are billed per request. Ask before using `aws ce`. Prefer budgets and billing data the user already has.
6. **Write outside the repo.** Default output directory: `~/infra-readiness-audit/<repo-name>/<YYYY-MM-DD>/`. Write inside the repo only if the user picks a path that is git-ignored.
7. **Only use tools already installed.** If a scanner (gitleaks, trivy, checkov, kubeconform) is missing, say so and fall back to the manual checks. Do not install anything without asking.

## Full audit workflow

### Phase 1: Reconnaissance (repo only, no live access)

Map what exists before judging anything. Record in `inventory.md`:

- Cloud provider(s) and accounts/projects referenced (Terraform providers, CI secrets names, kube contexts in docs).
- IaC: Terraform/OpenTofu roots, modules, backend blocks, environments (dirs, workspaces, tfvars). Helm charts, Kustomize overlays, raw manifests.
- CI/CD: every workflow file, which ones deploy, to which environment, using which credentials.
- Runtime: Kubernetes, serverless, VMs, managed DBs, queues, buckets that the code depends on.
- Observability: alerting, paging, error tracking, uptime checks, dashboards referenced in code or docs.
- Ownership signals: CODEOWNERS, README/runbooks, on-call docs.

Then decide which categories apply. Mark the rest `not_applicable` with a one-line reason.

### Phase 2: Checks

Run the checks in `CHECKS.md` for each applicable category, static first, then live (only after rule 2):

1. **IAM and access** (who can do what, long-lived keys, CI identity).
2. **Terraform state and drift** (remote state, locking, code vs. reality, manual console changes).
3. **Secrets** (in code, in git history, in CI, in manifests).
4. **CI/CD and production gates** (who can deploy, review requirements, workflow token permissions, risky triggers).
5. **Monitoring and alerting** (does a human get woken up, by what, for which services).
6. **Backups and DR** (do backups exist, retention, deletion protection, has anyone restored one).
7. **Cost guardrails** (budgets and alerts, idle resources).
8. **Review gaps on large or AI-assisted PRs** (merged without real review).
9. **Visibility into production changes** (audit logs on, who changed what recently, deploy trail).

For each candidate issue, capture: the command or file that shows it, the exact evidence (redacted), and what goes wrong because of it.

### Phase 3: Verify

Before anything goes in the report, re-check each candidate with a fresh look (a separate subagent if your platform supports it, otherwise a deliberate second pass that tries to disprove it):

- Is the evidence real and current (file still on the default branch, resource still exists)?
- Is there a compensating control you missed (an org policy, an SCP, a separate repo that manages it, branch rules set at org level)?
- Is the consequence concrete?

Assign each item one status:

- `confirmed`: evidence seen directly, consequence clear.
- `needs_validation`: depends on something you could not see (account-level settings, another repo, a human process). State exactly what must be checked and by whom.
- `rejected`: disproved. Keep it in the appendix so nobody re-raises it.

Only `confirmed` items get a priority.

### Phase 4: Report

Write `REPORT.md` using `REPORT-TEMPLATE.md`, plus `findings.json` (one object per item with `id`, `category`, `title`, `status`, `priority`, `evidence`, `consequence`, `fix`, `effort`). Keep prose and JSON consistent.

## Priorities (confirmed items only)

- **P0, fix this week:** current exposure or likely unrecoverable loss. Examples: a live-looking cloud key committed to git; a public bucket or database holding customer data; production database with no backups or no deletion protection; a workflow that runs untrusted PR code with deploy credentials; nobody alerted when production is down.
- **P1, fix this month:** one mistake or one departure away from an outage or a blind spot. Examples: many human owners/admins; long-lived CI keys instead of OIDC; local or unlocked Terraform state; deploys to prod with no review or approval; backups never restore-tested; no budget alert.
- **P2, hygiene:** real but low blast radius. Examples: actions not pinned to a SHA, missing resource limits, stale unused keys with no permissions, idle disks.

Rule of thumb: if you cannot say what concretely breaks, lower the priority.

## Fix guidance

For each confirmed item give the smallest change that removes the risk (one Terraform resource, one workflow block, one setting), roughly how long it takes (hours/days), and whether it is a good first task for an incoming DevOps hire. Describe fixes; never apply them.

## Anti-patterns

1. Dumping scanner output as findings. Every item needs a human-readable consequence.
2. Reporting "no X" without checking whether X is handled elsewhere (org level, another repo, a SaaS tool).
3. Guessing account settings you cannot see. Use `needs_validation`.
4. Treating AI-assisted code as a problem by itself. The finding is about review depth, not authorship.
5. Printing secret values, or testing whether a key works.
6. Running anything that changes state, even "harmless" ones like `terraform refresh`.
7. Claiming full coverage. Say what was not checked and why.
