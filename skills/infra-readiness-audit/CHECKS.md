# Checks reference

All commands are read-only. Replace `PROJECT`, `ACCOUNT_ID`, `OWNER/REPO`, `BILLING_ACCOUNT` as needed. Static checks need only the repo. Live checks need the user's explicit OK (SKILL.md rule 2). When a command fails for lack of permission, record `needs_validation` with the missing permission; do not escalate privileges.

---

## 1. IAM and access

**Why it matters:** in small teams, early "just give everyone admin" decisions stay forever. One leaked laptop key or one departed employee with owner access is the most common way a small company loses control of its cloud.

### Static
- Terraform IAM: `rg -n 'AdministratorAccess|"\*"|roles/owner|roles/editor' --glob '*.tf'` and review `Action = "*"` / `Resource = "*"` policies.
- CI credentials: `rg -n 'AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GOOGLE_CREDENTIALS|GCP_SA_KEY|credentials_json' .github/` (long-lived keys) vs. `id-token: write` + `aws-actions/configure-aws-credentials` with `role-to-assume` or `google-github-actions/auth` with `workload_identity_provider` (OIDC, preferred).
- OIDC trust scope: for each GitHub OIDC role in Terraform, check the trust condition pins `token.actions.githubusercontent.com:sub` to a specific repo and branch/environment, not `repo:ORG/*` or a bare `StringLike "*"`.

### Live: AWS
```bash
aws sts get-caller-identity
aws iam get-account-summary                       # users, MFA devices, AccountMFAEnabled (root MFA)
aws iam list-users --query 'Users[].[UserName,PasswordLastUsed]' --output table
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
for u in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam list-access-keys --user-name "$u" --query 'AccessKeyMetadata[].[UserName,AccessKeyId,Status,CreateDate]' --output text
  aws iam list-mfa-devices --user-name "$u" --query 'length(MFADevices)'
done
aws iam get-access-key-last-used --access-key-id AKIA...    # per key: stale keys
aws iam list-open-id-connect-providers
aws iam get-role --role-name ROLE --query 'Role.AssumeRolePolicyDocument'   # OIDC trust conditions
aws ec2 describe-security-groups --filters Name=ip-permission.cidr,Values=0.0.0.0/0 \
  --query 'SecurityGroups[].[GroupId,GroupName,IpPermissions[].FromPort]' --output text  # look for 22, 3389, 5432, 3306, 6379
aws s3control get-public-access-block --account-id ACCOUNT_ID
```
Findings to look for: root without MFA; humans with AdministratorAccess beyond 1-2 break-glass users; access keys older than 90 days or unused; IAM users for CI instead of OIDC roles; SSH/DB ports open to the internet.

### Live: GCP
```bash
gcloud config list
gcloud projects get-iam-policy PROJECT --format=json \
  | jq -r '.bindings[] | select(.role=="roles/owner" or .role=="roles/editor") | .role as $r | .members[] | "\($r)\t\(.)"'
gcloud iam service-accounts list --project PROJECT
gcloud iam service-accounts keys list --iam-account SA_EMAIL --managed-by=user   # user-managed keys = long-lived
gcloud iam workload-identity-pools list --location=global --project PROJECT
gcloud iam workload-identity-pools providers list --workload-identity-pool=POOL --location=global --project PROJECT \
  --format='table(name,attributeCondition)'                                          # empty condition = any repo can federate
gcloud compute firewall-rules list --project PROJECT --filter='sourceRanges:0.0.0.0/0 AND direction=INGRESS' \
  --format='table(name,network,allowed[].map().firewall_rule().list())'
```
Findings to look for: individual users as `roles/owner`; `roles/editor` on service accounts used by apps or CI; user-managed SA keys (especially old ones); the default compute SA with Editor still in use; WIF providers with no attribute condition.

### Live: Kubernetes
```bash
kubectl config current-context        # confirm with the user first
kubectl auth can-i --list
kubectl get clusterrolebindings -o json \
  | jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name as $n | (.subjects // [])[] | "\($n)\t\(.kind)\t\(.name)"'
```
GKE: `gcloud container clusters describe CLUSTER --region REGION --format='yaml(masterAuthorizedNetworksConfig,privateClusterConfig,workloadIdentityConfig,releaseChannel)'`
EKS: `aws eks describe-cluster --name CLUSTER --query 'cluster.resourcesVpcConfig.[endpointPublicAccess,publicAccessCidrs]'`
Findings: cluster-admin bound to individuals or default service accounts; public control plane open to 0.0.0.0/0; no workload identity (pods using node or key-file credentials).

---

## 2. Terraform state and drift

**Why it matters:** if state is on someone's laptop or unlocked, two people (or a person and CI) can corrupt it. If people change things in the console, the code stops describing reality and the next `apply` can undo a production fix.

### Static
```bash
rg -n 'backend\s+"' --glob '*.tf'                   # no backend block = local state
git ls-files | rg '\.tfstate(\.backup)?$|\.terraform/'  # state committed to git (P0 if it holds secrets)
rg -n 'dynamodb_table|use_lockfile' --glob '*.tf'    # S3 locking (use_lockfile is native S3 locking in TF >= 1.10)
git ls-files | rg '\.terraform\.lock\.hcl$'          # provider lock file committed?
rg -n 'required_version|required_providers' --glob '*.tf'
```
GCS backends lock natively; S3 backends need `use_lockfile = true` or a DynamoDB table. Also check for multiple environments sharing one state, and `terraform.tfvars` committed with secrets.

Scanners if installed: `trivy config .`, `checkov -d . --quiet`, `tflint`.

### Live (only if the root is already initialized and the user agrees)
```bash
terraform state list | wc -l
terraform plan -refresh-only -lock=false -input=false -no-color -detailed-exitcode   # exit 2 = real world differs from state
terraform plan -lock=false -input=false -no-color -detailed-exitcode                 # exit 2 = code differs from reality
```
`plan` does not change infrastructure, but it reads secrets into memory and may print sensitive values: redact before saving output. Never run `apply`, `refresh`, or any `state` write.

Manual-change signal (who changed infra outside Terraform/CI in the last 7 days):
- AWS: `aws cloudtrail lookup-events --lookup-attributes AttributeKey=ReadOnly,AttributeValue=false --max-results 50 --query 'Events[].[EventTime,EventName,Username]' --output text` and compare `Username` to the CI role.
- GCP: `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity"' --project PROJECT --freshness=7d --limit=50 --format='table(timestamp,protoPayload.methodName,protoPayload.authenticationInfo.principalEmail)'`

---

## 3. Secrets

**Why it matters:** a secret in git history stays there after you delete the file, and every clone, fork, and CI cache has a copy.

```bash
gitleaks git --redact --no-banner .        # gitleaks >= 8.19; older: gitleaks detect --source . --redact
trufflehog git file://. --no-verification  # --no-verification: do NOT let the tool test keys against live APIs
```
Fallback without scanners (also scans history):
```bash
git log -p --all | rg -n 'AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|"private_key_id"|ghp_[A-Za-z0-9]{36}|github_pat_|xox[baprs]-|sk_live_|AIza[0-9A-Za-z_-]{35}' | cut -c1-120
git ls-files | rg '(^|/)\.env($|\.)|\.pem$|\.p12$|\.key$|service-account.*\.json$|credentials\.json$'
```
Also check: secrets as plain `env:` values in workflow files or Kubernetes manifests; Helm `values.yaml` with passwords; Docker images built with `ARG`/`ENV` secrets; whether apps read from Secret Manager / SSM / Vault / External Secrets at all (`rg -n 'secretmanager|ssm:GetParameter|external-secrets|vault' .`).

Report secret type, path, commit, and whether it is still on the default branch. The fix is always "rotate, then remove", not just "delete the file".

---

## 4. CI/CD and production gates

**Why it matters:** without a gate, anyone with push access (or any compromised dependency in a workflow) can ship to production.

### Static (each file in `.github/workflows/`)
- No top-level `permissions:` block → the token gets the repo's default permissions. Look for least-privilege (`contents: read`).
- `pull_request_target` or `workflow_run` that checks out PR code (`ref: ${{ github.event.pull_request.head.sha }}`) and has secrets: P0 candidate.
- `${{ github.event.* }}` (titles, branch names, bodies) interpolated directly inside `run:`: script injection.
- Third-party actions pinned to a tag/branch instead of a full commit SHA: `rg -n 'uses: [^./][^@]+@(v?[0-9]|main|master)' .github/workflows`
- Deploy jobs: do they use `environment: production`? Do they run on every push to main with no approval?
- Is there a staging environment that prod deploys must pass through?

### Live (GitHub, read-only API)
```bash
gh api repos/OWNER/REPO/actions/permissions/workflow          # default GITHUB_TOKEN permissions
gh api repos/OWNER/REPO/environments --jq '.environments[] | {name, protection_rules}'
gh api repos/OWNER/REPO/rulesets
gh api repos/OWNER/REPO/branches/main/protection               # needs admin; 404/403 → needs_validation
gh api repos/OWNER/REPO/collaborators --jq '.[] | select(.permissions.admin) | .login'
```
Findings: prod environment without required reviewers; main branch with no required review; force-push allowed on main; many admins.

---

## 5. Monitoring and alerting

**Why it matters:** the question is not "do we have dashboards" but "if production goes down at 3am, who finds out, and how".

### Static
`rg -n -i 'pagerduty|opsgenie|alertmanager|sentry|datadog|grafana|betterstack|uptime|healthcheck|statuspage' --glob '!node_modules'` and look for alert rules in Terraform (`aws_cloudwatch_metric_alarm`, `google_monitoring_alert_policy`, `PrometheusRule`).

### Live
- AWS: `aws cloudwatch describe-alarms --query "MetricAlarms[].[AlarmName,StateValue,length(AlarmActions)]" --output text` (0 actions = the alarm notifies nobody), `aws sns list-subscriptions --query 'Subscriptions[].[TopicArn,Protocol,Endpoint]' --output text`, `aws route53 list-health-checks --query 'length(HealthChecks)'`.
- GCP: `gcloud monitoring policies list --project PROJECT --format='table(displayName,enabled,notificationChannels.len())'`, `gcloud beta monitoring channels list --project PROJECT --format='table(displayName,type,enabled)'`, `gcloud monitoring uptime list-configs --project PROJECT`.
- Kubernetes: `kubectl get prometheusrules -A 2>/dev/null`; pods without probes: `kubectl get deploy -A -o json | jq -r '.items[] | select(any(.spec.template.spec.containers[]; .readinessProbe==null)) | "\(.metadata.namespace)/\(.metadata.name)"'`.

Ask the human (always `needs_validation` if unknown): who is paged, on what channel, and when was the last real alert acknowledged?

---

## 6. Backups and DR

**Why it matters:** a backup that was never restored is a hope, not a backup. Deletion protection is the cheapest insurance there is.

### Live: AWS
```bash
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,BackupRetentionPeriod,DeletionProtection,MultiAZ,PubliclyAccessible]' --output table
aws rds describe-db-clusters --query 'DBClusters[].[DBClusterIdentifier,BackupRetentionPeriod,DeletionProtection]' --output table
aws backup list-backup-plans
aws s3api get-bucket-versioning --bucket BUCKET
aws dynamodb describe-continuous-backups --table-name TABLE
```
### Live: GCP
```bash
gcloud sql instances list --project PROJECT
gcloud sql instances describe INSTANCE --project PROJECT \
  --format='yaml(settings.backupConfiguration,settings.availabilityType,settings.deletionProtectionEnabled,settings.ipConfiguration.ipv4Enabled)'
gcloud sql backups list --instance INSTANCE --project PROJECT --limit 5
gcloud storage buckets describe gs://BUCKET --format='yaml(versioning_enabled,soft_delete_policy)'
```
### Kubernetes
`kubectl get backups.velero.io -A 2>/dev/null`; stateful workloads on PVCs with no snapshot policy.

Static: Terraform `deletion_protection`, `backup_retention_period`, `prevent_destroy` lifecycle on databases and state buckets.

Ask the human: when was the last restore test, how long did it take, and what is the acceptable data loss (RPO, in time) and downtime (RTO)? Unknown = `needs_validation`, and "never" is a P1.

---

## 7. Cost guardrails

**Why it matters:** small teams find out about a runaway bill at the end of the month. A budget alert costs nothing to set up.

```bash
# AWS
aws budgets describe-budgets --account-id ACCOUNT_ID --query 'Budgets[].[BudgetName,BudgetLimit.Amount]' --output table
aws ec2 describe-volumes --filters Name=status,Values=available --query 'Volumes[].[VolumeId,Size,CreateTime]' --output text   # unattached disks
aws ec2 describe-addresses --query 'Addresses[?AssociationId==null].PublicIp' --output text                                     # idle Elastic IPs
aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,DBInstanceClass]' --output text
# aws ce get-cost-and-usage ... is billed per request: ask first.

# GCP
gcloud billing projects describe PROJECT --format='value(billingAccountName)'
gcloud billing budgets list --billing-account=BILLING_ACCOUNT
gcloud compute disks list --project PROJECT --filter='-users:*' --format='table(name,zone,sizeGb)'
gcloud compute addresses list --project PROJECT --filter='status=RESERVED' --format='table(name,address,region)'
```
Findings: no budget or budget with no alert recipients; non-prod environments running 24/7 at prod size; idle disks/IPs. Keep the tone factual: name the resource, not a guessed saving.

---

## 8. Review gaps on large or AI-assisted PRs

**Why it matters:** AI tools make it easy to open large PRs fast. The risk is not who wrote the code but whether a second person actually reviewed infra and deploy changes before they shipped.

```bash
gh pr list --repo OWNER/REPO --state merged --limit 100 \
  --json number,title,author,mergedBy,additions,deletions,createdAt,mergedAt,reviewDecision,reviews \
  > /tmp/prs.json
jq -r '.[] | select((.reviews | map(select(.state=="APPROVED")) | length) == 0) | "\(.number)\tno-approval\t+\(.additions)\t\(.title)"' /tmp/prs.json
jq -r '.[] | select(.author.login == .mergedBy.login) | "\(.number)\tself-merged\t\(.author.login)"' /tmp/prs.json
jq -r '.[] | select(.additions + .deletions > 500) | "\(.number)\tlarge\t+\(.additions)/-\(.deletions)\t\(.createdAt) -> \(.mergedAt)"' /tmp/prs.json
git log --since=90.days --format='%h%x09%an%x09%(trailers:key=Co-authored-by,valueonly,separator=%x2C)' \
  | rg -i 'claude|copilot|cursor|codex|devin|gemini|\[bot\]'
```
Cross-check with paths: flag PRs that touched `*.tf`, `.github/workflows/`, Helm/K8s manifests, IAM, or migrations and were merged with no approval or within minutes of opening. Note honestly that AI attribution in trailers is incomplete; report review depth, not authorship. Check whether CODEOWNERS covers infra paths: `cat .github/CODEOWNERS CODEOWNERS docs/CODEOWNERS 2>/dev/null`.

---

## 9. Visibility into production changes

**Why it matters:** during an incident the first question is "what changed?". If the answer takes an hour to find, the outage takes an hour longer.

- AWS: `aws cloudtrail describe-trails` and `aws cloudtrail get-trail-status --name TRAIL` (is a multi-region trail on and logging?).
- GCP: Admin Activity audit logs are always on; check Data Access logs for sensitive services: `gcloud projects get-iam-policy PROJECT --format=json | jq '.auditConfigs'`.
- Kubernetes: `kubectl rollout history deploy/NAME -n NS`; does the team know which image/commit is running? `kubectl get deploy -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}' | rg ':latest'` (`:latest`, or an image with no tag, means you cannot tell which build is running).
- CI: do deploys post to a channel (Slack/Teams step in the deploy workflow)? Are GitHub deployments/environments used so there is a history? `gh api repos/OWNER/REPO/deployments --jq '.[0:10][] | [.environment,.created_at,.sha[0:7]] | @tsv'`
- Manual changes: reuse the CloudTrail / Cloud Audit Logs queries from section 2.

Ask the human: for the last incident, how long did it take to find what changed?
