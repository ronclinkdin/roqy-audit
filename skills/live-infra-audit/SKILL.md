---
name: live-infra-audit
description: "Use when auditing a live VPS or cloud host, read-only. Docker/VPS, GCP, Terraform, audit logs, K8s/VPN access, scale guards, regression harness."
---

# Live Infra Audit

Audit what is actually running, not what the repo claims. Read-only always. Output: evidence-backed findings with P0/P1/P2, verdicts confirmed / needs_validation / rejected (same model as infra-readiness-audit).

## Hard safety rules

1. Read-only commands only: `docker ps/inspect/images`, `ss -tlnp`, `curl -I`, `openssl s_client`, `df`, `crontab -l`, `systemctl status`, cloud `list/get/describe` calls.
2. Never restart, stop, exec into, or reconfigure anything. Never send load or probes beyond a single HEAD request to the audited host.
3. Never print secret values. Redact to first 4 chars. Do not read secret file contents, only names/permissions.
4. Confirm the target host with the user before touching a server you were not pointed at.
5. Write output outside the repo: `~/infra-readiness-audit/<host>/<date>/live.md`.

## Procedure

### Phase 1: Inventory (one batched terminal call)

Run together: `hostname; uname -r; uptime`; `docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'`; `ss -tlnp | grep -v 127.0.0.1`; `docker images`; `df -h` on all mounts; `free -m`; `crontab -l`; `systemctl list-units --state=failed`.

### Phase 2: Checks (second batched call)

For a cloud target, the Terraform/IaC section and the Audit logs section are MANDATORY, not optional: run them even if the client did not mention IaC. If a section's tool is missing, state `not_applicable: <reason>` in the report instead of skipping silently.

| # | Check | Finding if |
|---|---|---|
| L1 | Public ports (`ss -tlnp`) | Service bound to 0.0.0.0 that should be localhost (DB, admin UI, debug port). Verify reachability with `curl -sI http://<ip>:<port>` before calling it a finding |
| L2 | TLS (`openssl s_client ... -dates`) | Cert expired or <14 days left |
| L3 | Restart policies (`docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' $(docker ps -q)`) | `no` on a prod container |
| L4 | Image freshness | Prod image >6 months old or unpinned `:latest` on stateful services |
| L5 | Backups | No backup cron, or output dirs empty/stale >7 days |
| L6 | Disk (`df -h`) | Any filesystem >85% |
| L7 | Failed units | Any failed service |
| L8 | Firewall (`ufw status`) | Inactive while public services listen |
| L9 | SSH (`grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*`) | Password auth on or root password login |

### Phase 3: Verify then report

Verdicts are a closed set: `confirmed`, `needs_validation`, `rejected`. No other words exist — `partial`, `clean`, `ok`, `warning` are forbidden in headings and findings. If you cannot classify, the verdict is `needs_validation`. Agents left free will invent verdict words; the regression harness rejects them, so never write them.

Re-run each command, look for a compensating control (reverse proxy in front, firewall elsewhere). Write `live.md`: inventory, findings with exact redacted command output, consequence, smallest fix, effort, and an execution order that groups changes sharing one window (e.g. firewall rules together).

## Deliverable packaging

For client-facing audits, package the run as the roqy-audit toolkit does
(/root/roqy-audit): skills/ + docs/AGENT-RUNBOOK.md (per-client step order) +
docs/CLIENT-ONBOARDING-AWS.md (screen-by-screen read-only identity creation,
send to client) + docs/CONTEXT-BUDGET.md (phase-per-call, output-to-files,
filtered commands, resume protocol). Reuse those docs as templates instead of
rewriting them per client.

## Cloud target (AWS/GCP) — verified pipeline

For a cloud account, the audit runs the same phases against `list/describe` APIs after a read-only identity is connected:

1. Connect: AWS via access key env vars + `aws sts get-caller-identity`; GCP via `gcloud auth login --no-launch-browser` (run it in a pty background terminal, feed the browser code with process submit). Verify with `gcloud auth list` — the login can save the token even when gcloud prints a confusing error afterward, so always re-check auth list before retrying.
2. An OAuth verification code is one-time and bound to the PKCE challenge of the exact login link that generated it. A code pasted from a different session or an earlier link fails with invalid_grant; ask for a fresh code from the current link, never reuse.
3. First commands: `gcloud projects list`, `gcloud projects get-iam-policy`, `gcloud iam service-accounts list`, `gcloud storage ls`, `gcloud billing accounts list`. Disabled APIs are a finding-adjacent note, not a blocker — report what the enabled surface is.
4. A clean sandbox account proves the pipeline, not the value. State that explicitly; real findings need a dirty environment (a real client or an aged account).
5. Billing/credits: `gcloud billing accounts list` (or the cloudbilling REST endpoint with `gcloud auth print-access-token`) is the ground truth for whether credits/billing exist; a user's memory of credits is not. Empty list = no billing account linked to that identity, check for another Google account.

## GCP checks (validated on a live canary project)

| # | Check | Command | Finding if |
|---|---|---|---|
| G1 | Open firewall | `gcloud compute firewall-rules list --format='table(name,sourceRanges.list(),allowed[].map().firewall_rule().list())'` | 0.0.0.0/0 allowing tcp:22/3389 or management ports (check default rules too) |
| G2 | Over-privileged SA + exported key | `gcloud projects get-iam-policy $P --format='value(bindings.role,bindings.members)'` + `gcloud iam service-accounts keys list --iam-account=<sa>` | SA with roles/editor or owner AND a user-managed key |
| G3 | VM scopes | `gcloud compute instances describe <vm> --zone=<z> --format='value(serviceAccounts[0].scopes)'` | cloud-platform scope on a running VM |
| G4 | Budget alert | `gcloud billing budgets list --billing-account=<id>` | API disabled or zero budgets |
| G5 | Disk backups | `gcloud compute resource-policies list` | No snapshot schedule |
| G6 | Public bucket object | `curl -s -o /dev/null -w '%{http_code}' https://storage.googleapis.com/<bucket>/<object>` | 200 on an object that should be private. Never test with a write call; org policies block allUsers bindings (HTTP 412) — that is a compensating control, mark rejected |

Set `CLOUDSDK_CORE_PROJECT` explicitly for compute commands — gcloud silently errors asking for a project otherwise.

## Canary validation pattern

To validate the audit skill itself: build a deliberately dirty throwaway environment (open firewall rule, over-privileged SA with an exported key, cloud-platform VM scope, fake secret in a bucket), run the full audit, and confirm every planted issue is detected AND that compensating controls get findings rejected, not confirmed. A clean sandbox only proves the pipeline. After a canary run, fold the exact working commands into this skill immediately — that is the moment the commands are freshest and proven. Delete exported canary keys from disk when done.

## Terraform / IaC layer (validated on a live canary)

| # | Check | Command | Finding if |
|---|---|---|---|
| T1 | State exists and is real | `terraform state list` in the client's IaC root | Empty state with live resources = IaC is decoration, everything is console-managed |
| T2 | Drift | `terraform plan -input=false` after `terraform import` of key resources | Plan shows changes nobody declared = manual console changes |
| T3 | State security | Inspect backend config; local state file present? | State on disk unencrypted, no remote locking |

Validated pitfalls:
- An empty state + `plan -refresh-only` returns "No changes" — a false clean bill. Import the key resources first, then judge.
- google provider 6.x import ID for compute instances must be the full path `projects/<p>/zones/<z>/instances/<name>`; short `zone/name` fails with "non-existent remote object". Provider-level `zone` must be set or imports fail with "Cannot determine zone".
- Auth for local runs: `export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)` — no service account needed for read-only audit.
- Never run `terraform apply` in an audit. Plan and refresh-only are read-only; import writes only local state.

## Audit logs and change visibility (GCP, validated)

| # | Check | Command | Finding if |
|---|---|---|---|
| A1 | Admin activity trail | `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity" AND timestamp>="<recent>"' --limit=5 --format='value(protoPayload.methodName,timestamp)'` | Empty = changes invisible |
| A2 | Attribution | Same query with `--format='value(protoPayload.authenticationInfo.principalEmail)'` | Entries with no principal = shared accounts hide who did what |
| A3 | Watching the logs | `gcloud logging sinks list` + `curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" 'https://monitoring.googleapis.com/v3/projects/<p>/alertPolicies'` | Only the default _Required sink and empty alertPolicies = logs exist, nobody watches |
| A4 | Data access logs | `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Fdata_access"' --limit=1` | Empty = bucket/secret reads unlogged. Default OFF in GCP |

Logs being on by default is not visibility. Always check who reads them (A3) and whether data access is logged (A4).

## AWS checks (validated on a live canary account)

| # | Check | Command | Finding if |
|---|---|---|---|
| W1 | Public S3 buckets | `aws s3api list-buckets`, then per bucket `get-bucket-policy-status` (IsPublic true) + anonymous `curl -s -o /dev/null -w '%{http_code}' https://<bucket>.s3.<region>.amazonaws.com/<key>` | IsPublic true or anonymous 200 |
| W2 | Open security groups | `aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpProtocol==`tcp` && IpRanges[?CidrIp==`0.0.0.0/0`]]].[GroupId,GroupName]'` | tcp:22/3389/admin ports from 0.0.0.0/0 |
| W3 | Long-lived IAM keys | `aws iam list-users` then `list-access-keys --user-name <u>` with CreateDate | Keys older than 90 days, Active keys for departed users |
| W4 | Root MFA | `aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'` | 0 = root without MFA (P0) |
| W5 | Account-level S3 block | `aws s3control get-public-access-block --account-id <id>` | NoSuchPublicAccessBlockConfiguration = no account guardrail (P2) |
| W6 | CloudTrail | `aws cloudtrail describe-trails --query 'trailList[].Name'` | Zero trails = no change history (P1) |
| W7 | Budgets | `aws budgets describe-budgets --account-id <id>` | None = cloud bills with no alert (P1) |
| W8 | Config / GuardDuty | `aws configservice describe-configuration-recorders` + `aws guardduty list-detectors` | Both empty = no guardrails (P2) |
| W9 | EKS public endpoint | `aws eks describe-cluster --name <c> --query 'cluster.resourcesVpcConfig.endpointPublicAccess'` | True without CIDR restriction. This is the EKS DEFAULT, not a misconfiguration — the most common real-world exposure |

AWS lessons (validated): new buckets are BucketOwnerEnforced, so object ACLs cannot make things public — check the bucket POLICY, not ACLs. Verify an identity is read-only with a write probe (create-bucket must return AccessDenied). PowerUserAccess can plant S3/EC2 findings but cannot write IAM; IAM findings are planted by the account owner and detected read-only via SecurityAudit.

## Kubernetes workload checks (validated on live GKE and EKS canaries)

Run with kubectl, read-only. EXCLUDE system namespaces (kube-system, kube-public, kube-node-lease, gmp-system, gke-managed*) from workload findings: their pods are privileged/hostPath by design and flagging them drowns the report in false positives. Cover system namespaces with one summary line.

| # | Check | Command | Finding if |
|---|---|---|---|
| K7 | Privileged containers | `kubectl get pods -A -o json` filtered to user namespaces, check securityContext.privileged | Any workload pod privileged = container escape path |
| K8 | hostPath volumes | Same dump, check spec.volumes[].hostPath | hostPath / or /var/run/docker.sock = node takeover |
| K9 | RBAC over-grant | `kubectl get clusterrolebindings -o json`, bindings to cluster-admin with ServiceAccount subjects | Workload SA with cluster-admin |
| K10 | Public exposure | `kubectl get svc -A --field-selector spec.type=LoadBalancer` | LB on an admin/internal panel |
| K11 | Image + limits | Same pod dump: :latest or untagged image, empty resources.limits | Unpinned images, no limits = OOM and supply-chain risk |
| K12 | NetworkPolicy | `kubectl get netpol -A` | Zero policies in user namespaces = any pod reaches any pod. This is the default on fresh clusters |
| K13 | Token automount | Same pod dump: automountServiceAccountToken not false on pods not using the API | Every pod holds a live API token it never uses |

Detection: one python pass over the pods JSON, flag privileged/hostPath/:latest/missing limits, under 30 lines of output.

## Access architecture (Kubernetes / private environments) — discovery questions

For clients running EKS/GKE behind a VPN. Map the access path before judging. needs_validation by default; confirmed only when you saw the config yourself.

| # | Question | Finding if |
|---|---|---|
| K1 | Cluster API endpoint public or private? (`aws eks describe-cluster`) | Public API with broad CIDR allowlist |
| K2 | How does CI/CD reach the private cluster? | Long-lived kubeconfig on a runner or credentials in CI vars. Correct: in-VPC runner, OIDC role, or GitOps pull (ArgoCD/Flux) |
| K3 | How do external vendors get access? | Shared VPN accounts or shared kubeconfig = no attribution, no revocation. Correct: per-person temporary IAM role + SSM Session Manager |
| K4 | VPN cloud-native or third-party? | Third-party acceptable; check manual route tables, no SG references, no MFA on the VPN |
| K5 | Who has cluster-admin? (`kubectl get clusterrolebindings`, read-only) | More than 2-3 humans, or a vendor |
| K6 | Jenkins or legacy CI with prod credentials? | Jenkins master with static cloud keys = one compromised box owns prod. Migration path: GitOps + ephemeral runners |

## Client-favorite checks (add to every audit)

| # | Check | Command / question | Finding if |
|---|---|---|---|
| X1 | AI/LLM key sprawl | grep env files for key prefixes (names only); ask who pays and whether keys are per-service | Shared company key, no spend caps. One leaked key = unlimited bill. Leads the pitch — everyone has AI keys, nobody governs them |
| X2 | Bus factor / offboarding | Ask what breaks if the one person who knows the deploy leaves | Critical paths held by one person, no offboarding checklist |
| X3 | PII in logs | Sample app logs and third-party loggers for request bodies, emails, tokens | Customer data in logs with retention = a breach that already happened, just not discovered |
| X4 | Dependency supply chain | `npm audit --omit=dev`, lockfile age, Dependabot/Renovate | Lockfile untouched for months, prod on EOL runtime |
| X5 | Secrets rotation | `aws iam list-access-keys` / GCP key `validAfterTime` | Keys older than 90 days, no rotation policy |
| X6 | Domain/DNS blast radius | `dig NS <domain>`; ask about registrar 2FA and who has access | Shared or 2FA-less registrar account. A hijacked DNS beats every other finding |

## Scale guard (large environments)

A 200-container host or a 50-project org can flood the context and kill the run. Mandatory rules:

1. Count before you list: `| wc -l` first, then the query with `--limit`. Over 50 resources = sample top 20 by exposure plus the count in the report.
2. One phase per tool call. A timeout loses one phase; files on disk are the resume point.
3. Raw output goes to files (`~/infra-readiness-audit/<target>/<date>/raw/`), never to the conversation. The report cites file paths plus key lines.
4. Hard caps per command: `--limit 20` on cloud lists, `head -20` on docker/ss/df, `-m 5` on curl, `ConnectTimeout=15` on openssl. A hung check is killed, marked needs_validation, the run continues.
5. Bounded fan-out: at most 10 VMs per audit, chosen by exposure (public IP first), sampling stated in the report.
6. Resume protocol: findings.json is the source of truth; the report is generated from it last.
7. Crash test: over 100 resources, run recon alone first. Distilled recon over ~200 lines = split the target by project/zone and audit in slices.

## Provisioning canaries (when the audit needs a throwaway environment)

- After every create command, verify the resource exists with a get/list call before building on it. Never confirm success from the create command's own output — filter pipes (head, tail) swallow AccessDenied errors and produce false 'ready' states that fail minutes later at a deeper step.
- IAM write scopes are narrower than they look: PowerUserAccess denies iam:CreateRole and iam:PassRole. Have the account owner attach a scoped inline policy (create/attach/pass on eks* roles only) rather than admin.
- simulate-principal-policy can report allowed before a freshly attached inline policy propagates — re-probe with a real call before retrying the blocked operation.
- A cloud resource can stay ACTIVE while its referenced IAM role is missing; recreate the same-name role if a child-resource create reports the role not found.
- EKS on a fresh account needs eksClusterRole (AmazonEKSClusterPolicy) + eksNodeRole (AmazonEKSWorkerNodePolicy, AmazonEKS_CNI_Policy, AmazonEC2ContainerRegistryReadOnly) + instance profile before anything else.

## Regression harness

The audit output validator lives at /root/roqy-audit/harness/run_audit_harness.py; per-target scenario runner at /root/roqy-audit/harness/run_scenarios.py (repo / vps / gcp scenarios, gke opt-in). `validate <dir>` checks a run's artifacts (report exists, under 120 lines, no secret/token leaks, findings.json schema, priority only on confirmed, planted-finding coverage, per-family keyword coverage as WARN for old reports). `live` runs the skill end-to-end via `hermes chat -s live-infra-audit --yolo` against the canary project and validates the output. Run it after every skill change — it caught a priority-on-needs_validation violation and an invented-verdict heading on its first passes. Gate on artifact validation, not on the hermes process exit code: max-turns exhaustion after the report is written still counts as success. Keep the repo copy and this profile copy of SKILL.md in sync (cp after every edit).

## Priorities

- **P0:** public admin/DB port, expired TLS on the main domain, no backups of customer data, disk >95%.
- **P1:** no restart policy on prod container, stale backups, disk >85%, password SSH auth, no firewall.
- **P2:** stale images, dead containers, pending reboot, lab containers with `no` restart policy.

## Pitfalls

- Verify backups by listing the OUTPUT files, not by reading the cron line — a backup script can exist, be scheduled, and still produce empty directories because its config step silently failed. Empty backup dirs are P0, not a note.
- Check `/etc/ssh/sshd_config.d/*.conf` in addition to sshd_config — cloud-init drops overrides there, and the main file can look safe while the effective config allows passwords.
- On a reverse-proxy host, check the proxy's own admin port (Nginx Proxy Manager defaults to 81 on 0.0.0.0) — it is the most commonly forgotten public surface.
- When enabling a firewall on a host running many services, apply all rules in one change window and verify every public service immediately after; a half-applied firewall is how a proxy or webhook gets silently cut off.
