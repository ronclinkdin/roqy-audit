---
name: live-infra-audit
description: "Use when auditing a live VPS or cloud host, read-only. Docker/VPS, GCP, AWS, Terraform, audit logs, K8s/VPN access, scale guards, regression harness. Checks live in references/ — load only the file for the target's platform."
---

# Live Infra Audit

Audit what is actually running, not what the repo claims. Read-only always. Output: evidence-backed findings with P0/P1/P2, verdicts confirmed / needs_validation / rejected (same model as infra-readiness-audit).

## Hard safety rules

1. Read-only commands only: `docker ps/inspect/images`, `ss -tlnp`, `curl -I`, `openssl s_client`, `df`, `crontab -l`, `systemctl status`, cloud `list/get/describe` calls.
2. Never restart, stop, exec into, or reconfigure anything. Never send load or probes beyond a single HEAD request to the audited host.
3. Never print secret values. Redact to first 4 chars. Do not read secret file contents, only names/permissions.
4. Confirm the target host with the user before touching a server you were not pointed at.
5. Write output outside the repo: `~/infra-readiness-audit/<host>/<date>/live.md`.

## Which reference file to load (load ONLY the ones for this target)

| Target | Load |
|---|---|
| Docker/VPS host | `references/CHECKS-VPS.md` |
| GCP project | `references/CHECKS-GCP.md` |
| AWS account | `references/CHECKS-AWS.md` |
| Kubernetes cluster (GKE/EKS) | `references/CHECKS-K8S.md` |
| Terraform/IaC present | `references/CHECKS-IAC.md` |
| Any client audit | `references/CHECKS-CLIENT.md` (interview checks, always include) |

Always load: `references/RECONNAISSANCE.md` (phase 1) and `references/VALIDATION-AND-REPORTING.md` (phase 3). Canary work adds `references/CANARY-VALIDATION.md`.

Never load all files at once — that is how the context floods. One target, its file, plus CHECKS-CLIENT.md.

## Procedure

### Phase 1: Inventory (one batched terminal call)

Run together: `hostname; uname -r; uptime`; `docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'`; `ss -tlnp | grep -v 127.0.0.1`; `docker images`; `df -h` on all mounts; `free -m`; `crontab -l`; `systemctl list-units --state=failed`. For cloud targets, the equivalent is the platform's list/describe calls from the reference file.

### Phase 2: Checks (second batched call)

Run the checks from the loaded reference file(s). For a cloud target, the IaC and audit-log sections are MANDATORY, not optional: run them even if the client did not mention IaC. If a section's tool is missing, state `not_applicable: <reason>` in the report instead of skipping silently.

### Phase 3: Verify then report

Full rules in `references/VALIDATION-AND-REPORTING.md`. Summary:

Verdicts are a closed set: `confirmed`, `needs_validation`, `rejected`. No other words exist — `partial`, `clean`, `ok`, `warning` are forbidden in headings and findings. If you cannot classify, the verdict is `needs_validation`. Agents left free will invent verdict words; the regression harness rejects them, so never write them.

Re-run each command, look for a compensating control (reverse proxy in front, firewall elsewhere). Write `live.md`: inventory, findings with exact redacted command output, consequence, smallest fix, effort, and an execution order that groups changes sharing one window (e.g. firewall rules together).

Heading format is strict: `### <id> — <title> (CONFIRMED, P0)` where the verdict is exactly CONFIRMED, NEEDS_VALIDATION, or REJECTED. Sections that could not run get a line `not_applicable: <reason>`, never silence and never a new verdict word.

## Scale guard (large environments)

A 200-container host or a 50-project org can flood the context and kill the run. Mandatory rules:

1. Count before you list: `| wc -l` first, then the query with `--limit`. Over 50 resources = sample top 20 by exposure plus the count in the report.
2. One phase per tool call. A timeout loses one phase; files on disk are the resume point.
3. Raw output goes to files (`~/infra-readiness-audit/<target>/<date>/raw/`), never to the conversation. The report cites file paths plus key lines.
4. Hard caps per command: `--limit 20` on cloud lists, `head -20` on docker/ss/df, `-m 5` on curl, `ConnectTimeout=15` on openssl. A hung check is killed, marked needs_validation, the run continues.
5. Bounded fan-out: at most 10 VMs per audit, chosen by exposure (public IP first), sampling stated in the report.
6. Resume protocol: findings.json is the source of truth; the report is generated from it last.
7. Crash test: over 100 resources, run recon alone first. Distilled recon over ~200 lines = split the target by project/zone and audit in slices.

## Priorities

- **P0:** public admin/DB port, expired TLS on the main domain, no backups of customer data, disk >95%.
- **P1:** no restart policy on prod container, stale backups, disk >85%, password SSH auth, no firewall.
- **P2:** stale images, dead containers, pending reboot, lab containers with `no` restart policy.

## Pitfalls

- Verify backups by listing the OUTPUT files, not by reading the cron line — a backup script can exist, be scheduled, and still produce empty directories because its config step silently failed. Empty backup dirs are P0, not a note.
- Check `/etc/ssh/sshd_config.d/*.conf` in addition to sshd_config — cloud-init drops overrides there, and the main file can look safe while the effective config allows passwords.
- On a reverse-proxy host, check the proxy's own admin port (Nginx Proxy Manager defaults to 81 on 0.0.0.0) — it is the most commonly forgotten public surface.
- When enabling a firewall on a host running many services, apply all rules in one change window and verify every public service immediately after; a half-applied firewall is how a proxy or webhook gets silently cut off.

## Canary validation pattern

Full pattern and provisioning lessons in `references/CANARY-VALIDATION.md`. Summary: build a deliberately dirty throwaway environment, run the full audit, confirm every planted issue is detected AND compensating controls get findings rejected, not confirmed. A clean sandbox only proves the pipeline. After a canary run, fold the exact working commands into the relevant reference file immediately. Delete exported canary keys from disk when done.

## Regression harness

Full details in `references/VALIDATION-AND-REPORTING.md`. The audit output validator lives at /root/roqy-audit/harness/run_audit_harness.py; per-target scenario runner at /root/roqy-audit/harness/run_scenarios.py (repo / vps / gcp scenarios, gke opt-in). Run it after every skill change — it caught a priority-on-needs_validation violation and an invented-verdict heading on its first passes. Gate on artifact validation, not on the hermes process exit code. Keep the repo copy and this profile copy of the skill in sync (cp after every edit).

## Deliverable packaging

For client-facing audits, package the run as the roqy-audit toolkit does (/root/roqy-audit): skills/ + docs/AGENT-RUNBOOK.md (per-client step order) + docs/CLIENT-ONBOARDING-AWS.md (screen-by-screen read-only identity creation, send to client) + docs/CONTEXT-BUDGET.md (phase-per-call, output-to-files, filtered commands, resume protocol). Reuse those docs as templates instead of rewriting them per client.
