# Live Infra Audit — AWS <canary-account> (canary)
Date: 2026-11-04. Region eu-central-1. Auditor: roqy-audit (SecurityAudit + PowerUserAccess). Read-only verified: no resources changed. Raw output: raw/*.json in this directory.

## Inventory
| Resource | Count | Detail |
|---|---|---|
| IAM users | 1 | roqy-audit (audit identity, key created 2026-11-03) |
| IAM roles | 9 | 6 AWS service-linked + eksClusterRole, eksNodeRole, eksLambdaRole |
| S3 buckets | 3 | canary-authusers, canary-openai-credentials, write-probe-<canary-account> (audit probe artifact) |
| EC2 instances / ENIs / AMIs / key pairs | 0 | empty |
| EKS / ECS / RDS / ALB / ACM / VPC endpoints | 0 | empty |
| Lambda | 1 | canary-public-fn (python3.12, Function URL AuthType NONE) |
| ECR | 1 | canary-public-images (public pull policy) |
| Snapshots | 1 | snap-089f51e581a18f555 (public createVolumePermission) |
| Secrets Manager / KMS | 1 / 1 | canary/db-password; auto-secretsmanager-2 |
| CloudTrail / Config / GuardDuty / Budgets / Org | 0 | none |

## Findings

### F1 — Public S3 bucket with anonymous read AND write, AI-named (CONFIRMED, P0)
Evidence (get-bucket-policy, roqy-audit-canary-openai-credentials): `Principal:"*", Action:["s3:GetObject","s3:PutObject"]`; get-bucket-policy-status: `IsPublic: true`. Name contains "openai-credentials" (W41 attacker-magnet naming). Anonymous curl returns 403 only because no object exists; the grant is live and account PAB is off (F5).
Consequence: anyone on the internet can read and plant objects; AI-named buckets are grepped first by attackers (Sysdig 2026).
Fix: delete the bucket policy, enable account-level BlockPublicPolicy, rename bucket. Effort: 15 min.

If it stays: every object added later is one more thing a stranger can copy or overwrite, and the exposure window opened when the policy landed. This is the PREMINT 2022 vector.

### F2 — EC2 snapshot shared to "all" (CONFIRMED, P0)
Evidence (describe-snapshot-attribute snap-089f51e581a18f555 --attribute createVolumePermission): `CreateVolumePermissions: [{Group: all}]`; snapshot `Encrypted: false`.
Consequence: any AWS account can copy the full disk (Imperva 2019 / DNC 2016 vector); baked secrets exposed.
Fix: `ec2 modify-snapshot-attribute --operation-type remove --group-names all`. Effort: 2 min.

If it stays: the disk copy ages but its baked credentials often do not. Every AWS customer can boot this machine state. Imperva 2019 and DNC 2016 both started here.

### F3 — No CloudTrail (CONFIRMED, P1)
Evidence (describe-trails): `trailList: []`.
Consequence: zero change history; no forensics after an incident.
Fix: one multi-region trail to a dedicated bucket. Effort: 15 min.
not_applicable: W29 single-region check — no trails exist.

If it stays: incidents in other regions leave no trace and no forensic path. The account keeps its black box.

### F4 — No budget alerts (CONFIRMED, P1)
Evidence (describe-budgets --account-id <canary-account>): empty output, exit 0, zero budgets.
Consequence: leaked key = unlimited bill with no alert.
Fix: one cost budget with alert at $50. Effort: 5 min.

If it stays: the one alarm that fires on crypto-mining and exfiltration (a bill spike) does not exist. Cost anomalies surface as surprises.

### F5 — Account S3 Public Access Block all false (CONFIRMED, P2)
Evidence (s3control get-public-access-block): `BlockPublicAcls:false, IgnorePublicAcls:false, BlockPublicPolicy:false, RestrictPublicBuckets:false`.
Consequence: no account guardrail; F1/F7-style policies stay possible.
Fix: put-public-access-block, all four true. Effort: 5 min.

### F6 — ECR repository world-pullable (CONFIRMED, P1)
Evidence (get-repository-policy canary-public-images): `Principal:"*"`, Actions `GetDownloadUrlForLayer, BatchGetImage, BatchCheckLayerAvailability`.
Consequence: images (and any baked secrets) readable by anyone with the registry URI.
Fix: delete the repository policy. Effort: 2 min.

If it stays: every image, including any baked secrets in layers, is downloadable by anyone. The exposure compounds with every push.

### F7 — S3 bucket open to all AuthenticatedUsers (CONFIRMED, P1)
Evidence (get-bucket-policy, roqy-audit-canary-authusers): `Principal:"*"`, `s3:GetObject`, Condition `aws:PrincipalType=AuthenticatedUser`; policy-status `IsPublic: true`.
Consequence: "not public" but readable by every AWS account holder (Dow Jones 2026 pattern, 2.2M customers).
Fix: remove the AuthUsers statement. Effort: 5 min.

If it stays: any AWS account in the world can read the objects. The grant looks private in policy reviews and is public in practice. Dow Jones 2019: 2.2M records exposed this way.

### F8 — Lambda Function URL with AuthType NONE (CONFIRMED, P1)
Evidence (get-function-url-config canary-public-fn): `AuthType: NONE`, public lambda-url endpoint `<lambda-url>`.
Consequence: unauthenticated public invoke endpoint, invisible in SG/ALB audits.
Fix: set AuthType AWS_IAM or delete the URL config. Effort: 2 min.

If it stays: the function is a public endpoint invisible in normal API audits, reachable by anyone with the URL. Every future code change to it ships straight to the internet.

### F9 — No Config recorder, no GuardDuty (CONFIRMED, P2)
Evidence: `ConfigurationRecorders: []`, `DetectorIds: []`.
Consequence: no drift detection, no threat detection.
Fix: enable default Config recorder + GuardDuty detector. Effort: 30 min.

### F10 — EBS default encryption disabled (CONFIRMED, P2)
Evidence (get-ebs-encryption-by-default): `EbsEncryptionByDefault: false`.
Consequence: every future volume born unencrypted (F2's snapshot is unencrypted for the same reason).
Fix: enable EBS encryption by default. Effort: 5 min.

### F12 — SNS topic open to Publish from any principal (CONFIRMED, P2)
Evidence (get-topic-attributes canary-open-topic): policy Statement Sid "Open": `Principal:"*"`, Action `SNS:Publish`.
Consequence: any AWS account in the world can write to the topic; downstream subscribers receive attacker-controlled messages.
Fix: scope the policy Principal to the account root ARN. Effort: 5 min.

### F13 — Log group with no retention (CONFIRMED, P2)
Evidence (describe-log-groups): `/canary/never-expire` has no `retentionInDays` field = never expire.
Consequence: unbounded storage cost plus PII retained forever — two findings in one setting.
Fix: put-retention-policy, e.g. 90 days. Effort: 2 min.

### F11 — Security group open SSH 0.0.0.0/0 (NEEDS_VALIDATION, —)
Evidence (describe-security-groups): sg-0d54fdcc2e24687bd "audit-canary-open-ssh", tcp 22 from 0.0.0.0/0. describe-network-interfaces: `[]` — no ENI attached, zero instances in account.
Consequence: none today (unattached); becomes a public SSH door the moment an instance attaches.
Fix: remove the 0.0.0.0/0 ingress rule. Effort: 2 min.

## not_applicable lines
- not_applicable: W9/W18 EKS, W15/W28/W35/W42 EC2/SSM/ECS/ALB, W16 Org, W19-W21 AMI/RDS/ACM, W22 Cost Explorer access, W23 Bedrock, W39 public artifacts — resources absent or access denied.

## Checks that passed (evidence, no finding)
- W4 root MFA enabled (AccountMFAEnabled=1); W40 no root access keys (AccountAccessKeysPresent=0).
- W10/W31: all 9 role trust policies trust AWS services only (eks, lambda, ec2, autoscaling, support); no cross-account principals, no wildcard, no ExternalId risk.
- W24/W25: PassRole inline policy "test" scoped to eksClusterRole/eksNodeRole only; no NotAction statements; no wildcard PassRole.
- W26: KMS key policy is the standard Secrets Manager integration with kms:CallerAccount condition; secret has no resource policy; no external accounts.
- W27: no bucket notification configurations on any bucket.
- W3/W11: only IAM user is the fresh audit identity; key created 2026-11-03, active — no dormant users, no stale keys.
(+2 more, see hermes-run.log)

## Notes
- Write-probe bucket `roqy-audit-write-probe-<canary-account>` was created by a prior canary run to verify the read-only identity (create succeeded). Read-only mandate forbids deleting it; account owner should remove it.
- Secret `canary/db-password` has RotationEnabled=false but was created 2026-11-03, under the 90-day threshold — note only, not a finding.

## Execution order
1. Account PAB, then bucket policies; 2. snapshot unshare; 3. ECR/Lambda URL/SG; 4. CloudTrail/budget/Config/GuardDuty/EBS default; 5. cleanup probe bucket.
5. Cleanup: delete write-probe bucket.