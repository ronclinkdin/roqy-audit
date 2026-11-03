---
name: live-infra-audit
description: "Live read-only infrastructure audit against what is actually running: Docker/VPS servers (containers, exposed ports, TLS, backups, restart policies) and cloud accounts via read-only identity. Use when asked to audit a live server, check what is running in production, verify backups/TLS/ports on a VPS, or extend a repo audit with real runtime evidence. Companion to infra-readiness-audit (repo layer) and security-audit (code layer)."
---

# Live Infra Audit

Audit what is actually running, not what the repo claims. Read-only always. Output: evidence-backed findings with P0/P1/P2, same verdicts as infra-readiness-audit (confirmed / needs_validation / rejected).

## Hard safety rules

1. Read-only commands only: `docker ps/inspect/images/stats`, `ss -tlnp`, `curl -I`, `openssl s_client`, `df`, `crontab -l`, `systemctl status`, cloud `list/get/describe` calls.
2. Never restart, stop, exec into, or reconfigure anything. Never send load or probes to third-party endpoints beyond a single HEAD request to the audited host.
3. Never print secret values. Redact to first 4 chars. Do not read secret file contents, only names/permissions.
4. Ask before touching a server that is not the one you were pointed at. Confirm target host with the user first.
5. Write output outside the repo: `~/infra-readiness-audit/<host>/<date>/live.md`.

## Phase 1: Inventory (Docker/VPS target)

Run and record:
- `hostname; uname -r; uptime` — host, kernel, reboot age.
- `docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'` — every container, image, restarts.
- `docker ps -a --filter status=exited --format '{{.Names}}\t{{.Image}}'` — dead weight.
- `ss -tlnp | grep -v 127.0.0.1` — everything listening on a public interface.
- `docker images --format '{{.Repository}}:{{.Tag}}\t{{.CreatedSince}}'` — image age.
- `df -h / /mnt* 2>/dev/null; free -m` — disk and memory headroom.
- `crontab -l` and `ls /etc/cron*` — scheduled jobs (backups, renewals).
- `systemctl list-units --state=failed` — failed services.

## Phase 2: Checks

For a cloud target, the Terraform/IaC section and the Audit logs section are MANDATORY, not optional: run them even if the client did not mention IaC. Do not invent verdicts: only `confirmed`, `needs_validation`, `rejected` exist. If evidence is incomplete, use `needs_validation`, never a new word like `partial`.

| # | Check | Command | Finding if |
|---|---|---|---|
| L1 | Public ports | `ss -tlnp` | Service bound to 0.0.0.0 that should be 127.0.0.1 (DB, admin UI, unauthenticated API) |
| L2 | TLS | `curl -sI https://<host>` + `openssl s_client -connect <host>:443 -servername <host> 2>/dev/null \| openssl x509 -noout -dates` | Cert expired or <14 days left; http not redirected |
| L3 | Restart policy | `docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' $(docker ps -q)` | `no` on a prod container |
| L4 | Image freshness | `docker images` | Prod image >6 months old or `:latest` unpinned on stateful services |
| L5 | Backups exist | `crontab -l`, `ls -lt <backup dir> \| head` | No backup cron, or newest backup >7 days old |
| L6 | Disk headroom | `df -h` | Any filesystem >85% |
| L7 | Failed units | `systemctl list-units --state=failed` | Any failed service on the host |
| L8 | Kernel/host age | `uname -r; uptime` | Reboot pending >90 days or kernel far behind distro release |
| L9 | Firewall | `ufw status` or `iptables -L -n \| head -30` | No firewall rules with public services present |
| L10 | Auth surface | `ss -tlnp` for sshd; `grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config` | Password auth on, root login without key-only |

Cloud target (only with user-approved read-only identity): run the relevant sections of infra-readiness-audit CHECKS.md live (public buckets, security groups 0.0.0.0/0, unencrypted RDS, no backups, IAM keys >90d).

### GCP checks (validated on a live canary project, 2026-11-03)

| # | Check | Command | Finding if |
|---|---|---|---|
| G1 | Open firewall | `gcloud compute firewall-rules list --format='table(name,sourceRanges.list(),allowed[].map().firewall_rule().list())'` | Any rule with 0.0.0.0/0 allowing tcp:22/3389 or management ports |
| G2 | Over-privileged SA + exported keys | `gcloud projects get-iam-policy $P --format='value(bindings.role,bindings.members)'` + `gcloud iam service-accounts keys list --iam-account=<sa>` | SA with roles/editor or roles/owner AND a user-managed key |
| G3 | VM scopes | `gcloud compute instances describe <vm> --zone=<z> --format='value(serviceAccounts[0].scopes)'` | cloud-platform scope on a running VM |
| G4 | Budget alert | `gcloud billing budgets list --billing-account=<id>` | API disabled or zero budgets |
| G5 | Disk backups | `gcloud compute resource-policies list` | No snapshot schedule policies |
| G6 | Public buckets | `gcloud storage buckets list` + attempt `add-iam-policy-binding --member=allUsers` is NOT allowed (write). Instead: `curl -s -o /dev/null -w '%{http_code}' https://storage.googleapis.com/<bucket>/<object>` | 200 on an object that should be private |

GCP auth notes: `gcloud auth login --no-launch-browser` prints a URL; the verification code is session-bound (PKCE). A code from a different session or an earlier URL fails with `invalid_grant`. Always generate the URL and paste the code in the same run. Org policies can block `allUsers` bindings (HTTP 412) — that is a compensating control, mark the public-bucket finding `rejected`, not confirmed.

### Terraform / IaC layer (validated on the canary project, 2026-11-03)

| # | Check | Command | Finding if |
|---|---|---|---|
| T1 | State exists and is real | `terraform state list` in the client's IaC root | Empty state with live resources = IaC is decoration, everything is console-managed |
| T2 | Drift | `terraform plan -input=false` after `terraform import` of key resources | Plan shows changes nobody declared = manual console changes |
| T3 | State security | `ls` the backend config; local state file present? | State on disk unencrypted (contains secrets for some providers), no remote locking |

Validated pitfalls (do not repeat):
- An empty state + `plan -refresh-only` returns "No changes" — a false clean bill. Always import the key resources first, then judge.
- google provider 6.x import ID for compute instances must be the full path: `projects/<p>/zones/<z>/instances/<name>`. Short `zone/name` fails with "non-existent remote object".
- Provider-level `zone` must be set or instance imports fail with "Cannot determine zone".
- Auth for local runs: `export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)` — no service account needed for read-only audit.
- Never run `terraform apply` in an audit. Plan and refresh-only are read-only; import writes only local state.

### Audit logs and change visibility (GCP, validated 2026-11-03)

| # | Check | Command | Finding if |
|---|---|---|---|
| A1 | Admin activity trail works | `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity" AND timestamp>="<recent>"' --limit=5 --format='value(protoPayload.methodName,timestamp)'` | Empty = changes are invisible |
| A2 | Attribution | Same query with `--format='value(protoPayload.authenticationInfo.principalEmail)'` | Entries with no principal = shared/service accounts hide who did what |
| A3 | Log export/alerting | `gcloud logging sinks list` + `curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" 'https://monitoring.googleapis.com/v3/projects/<p>/alertPolicies'` | Only the default _Required sink and empty alertPolicies = logs exist but nobody is watching |
| A4 | Data access logs | `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Fdata_access"' --limit=1` | Empty = data access (bucket reads, secret reads) is not logged. Default OFF in GCP |

Validated on the canary: A1/A2 pass (firewall patch attributed to ronco@roqy.io), A3 fails (zero alert policies), A4 fails (no data access logs). The distinction matters: logs are on by default in GCP, watching them is not.

### Access architecture (Kubernetes / private environments) — discovery questions, not commands

These come up when a client runs EKS/GKE behind a VPN. The audit maps the access path before judging it. Ask, then verify against what they show:

| # | Question | Finding if |
|---|---|---|
| K1 | Is the cluster API endpoint public or private? `aws eks describe-cluster --name <c> --query 'cluster.endpoint'` + endpointPublicAccess | Public API with broad CIDR allowlist = internet-reachable control plane |
| K2 | How does CI/CD reach the private cluster? | Long-lived kubeconfig on a runner, or credentials in CI variables = static secret in the deploy path. Correct pattern: in-VPC runner, OIDC role, or GitOps pull (ArgoCD/Flux) |
| K3 | How do external vendors get access? | Shared VPN accounts or shared kubeconfig = no attribution, no revocation. Correct: per-person temporary IAM role + SSM Session Manager, no open ports |
| K4 | Is the VPN cloud-native or third-party? | Third-party VPN is acceptable but check: manual route tables, no SG references, no MFA on the VPN itself |
| K5 | Who has cluster-admin? `kubectl get clusterrolebindings` (read-only) | More than 2-3 humans with cluster-admin, or a vendor with it |
| K6 | Jenkins or equivalent legacy CI with prod credentials? | Jenkins master with static cloud keys = single compromised box owns prod. Migration path: GitOps + ephemeral runners |

These are needs_validation by default: the evidence is the client's own architecture description plus whatever read-only commands their identity allows. Only mark confirmed when you saw the config yourself.

### What clients ask about most (2026) — add to every audit

| # | Check | Command / question | Finding if |
|---|---|---|---|
| X1 | AI/LLM key sprawl | `grep -rn "sk-\|AIza\|ghp_" --include="*.env*" .` (names only), ask: who pays for OpenAI/Anthropic keys, are they per-person or shared? | Shared company key in a .env, no per-service keys, no spend caps. One leaked key = unlimited bill |
| X2 | Bus factor / offboarding | Ask: if the one person who knows the deploy left tomorrow, what breaks? List what only they hold (VPN certs, cloud console access, cron jobs on a personal account) | Critical paths held by one person, no offboarding checklist |
| X3 | PII in logs | Ask + sample: are request bodies, emails, or tokens written to app logs or third-party loggers (Sentry, Umami, CloudWatch)? | Customer data in logs with 30-90 day retention = a breach that already happened, just not discovered |
| X4 | Dependency supply chain | `npm audit --omit=dev 2>/dev/null \| tail -3`, check lockfile age, ask about Dependabot/Renovate | Lockfile untouched for months, no automated updates, prod running on EOL runtime |
| X5 | Secrets rotation | Ask: when was each cloud key last rotated? Check `aws iam list-access-keys` / GCP key `validAfterTime` | Keys older than 90 days, no rotation policy |
| X6 | Domain/DNS blast radius | `dig NS <domain>`, ask: where is DNS hosted, is 2FA on the registrar, who else has access? | Registrar account shared or without 2FA. A hijacked DNS beats every other finding |

X1 is the one that lands hardest with 2026 clients: everyone has AI keys, almost nobody governs them. Lead with it in the pitch.

## Scale guard (large environments)

A 200-container host or a 50-project org can flood the context and kill the run. These rules are mandatory, not optional.

1. **Count before you list.** Every listing command runs twice: first `| wc -l` (or `--format='value(name)' | wc -l`), then the actual query with `--limit`. If the count is over 50, sample: top 20 by relevance plus the count in the report. Never pull a full listing into the conversation.
2. **One phase per tool call.** Recon, checks, verify, report are separate calls. A timeout loses one phase; files on disk are the resume point. Never chain phases in one command.
3. **Raw output goes to files, not to the conversation.** `~/infra-readiness-audit/<target>/<date>/raw/`. The report cites file paths plus the key lines. The conversation holds only distilled findings.
4. **Hard caps per command.** `--limit 20` on cloud list calls, `head -20` on docker/ss/df output, `-m 5` on every curl, `ConnectTimeout=15` on every openssl. A hung check is killed, marked `needs_validation`, and the run continues.
5. **Per-resource fan-out is bounded.** Auditing N VMs: audit at most 10, chosen by exposure (public IP first), and state the sampling in the report. Never loop over all resources in one call.
6. **Resume protocol.** `ls ~/infra-readiness-audit/<target>/<date>/` shows which phases exist. Re-run only the missing phase. findings.json is the source of truth; the report is generated from it last.
7. **Crash test before a big run.** On a target with more than 100 resources, run Phase 1 recon alone first. If the recon output fits (under ~200 lines distilled), proceed. If not, split the target by project/zone and audit in slices.

## Phase 3: Verify

For each candidate: re-run the command, confirm the evidence is current, look for a compensating control (reverse proxy in front, firewall elsewhere, backup verified elsewhere). Assign each item exactly one of three verdicts: `confirmed`, `needs_validation`, `rejected`. No other words exist. `partial`, `clean`, `ok`, `warning` are forbidden in headings and findings. If you cannot classify, the verdict is `needs_validation`. Only confirmed get a priority.

Tool paths on this host: gcloud at `/tmp/google-cloud-sdk/bin/gcloud`, terraform at `/tmp/terraform`. If a section's tool is missing, state `not_applicable: <reason>` in the report instead of skipping silently.

## Priorities

- **P0:** public DB/admin port, expired TLS on the main domain, no backups of customer data, disk >95%.
- **P1:** no restart policy on prod container, backups stale >7d, disk >85%, password SSH auth, no firewall.
- **P2:** stale images, dead containers, pending reboot, unpinned :latest on stateless services.

## Report

Write `live.md`: inventory table, findings with exact command output as evidence (redacted), consequence, smallest fix, effort. Keep it under one page per 10 findings.
