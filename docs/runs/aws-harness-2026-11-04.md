# Live Infra Audit — AWS 856114194841 (canary)
Date: 2026-11-04. Region eu-central-1. Auditor: roqy-audit (SecurityAudit + PowerUserAccess). Read-only verified: no resources changed. Raw output: raw/*.json in this directory.

## Inventory
| Resource | Count | Detail |
|---|---|---|
| IAM users | 1 | roqy-audit (audit identity, key created 2026-11-03) |
| IAM roles | 9 | 6 AWS service-linked + eksClusterRole, eksNodeRole, eksLambdaRole |
| S3 buckets | 3 | canary-authusers, canary-openai-credentials, write-probe-856114194841 (audit probe artifact) |
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

### F2 — EC2 snapshot shared to "all" (CONFIRMED, P0)
Evidence (describe-snapshot-attribute snap-089f51e581a18f555 --attribute createVolumePermission): `CreateVolumePermissions: [{Group: all}]`; snapshot `Encrypted: false`.
Consequence: any AWS account can copy the full disk (Imperva 2019 / DNC 2016 vector); baked secrets exposed.
Fix: `ec2 modify-snapshot-attribute --operation-type remove --group-names all`. Effort: 2 min.

### F3 — No CloudTrail (CONFIRMED, P1)
Evidence (describe-trails): `trailList: []`.
Consequence: zero change history; no forensics after an incident.
Fix: one multi-region trail to a dedicated bucket. Effort: 15 min.
not_applicable: W29 single-region check — no trails exist.

### F4 — No budget alerts (CONFIRMED, P1)
Evidence (describe-budgets --account-id 856114194841): empty output, exit 0, zero budgets.
Consequence: leaked key = unlimited bill with no alert.
Fix: one cost budget with alert at $50. Effort: 5 min.

### F5 — Account S3 Public Access Block all false (CONFIRMED, P2)
Evidence (s3control get-public-access-block): `BlockPublicAcls:false, IgnorePublicAcls:false, BlockPublicPolicy:false, RestrictPublicBuckets:false`.
Consequence: no account guardrail; F1/F7-style policies stay possible.
Fix: put-public-access-block, all four true. Effort: 5 min.

### F6 — ECR repository world-pullable (CONFIRMED, P1)
Evidence (get-repository-policy canary-public-images): `Principal:"*"`, Actions `GetDownloadUrlForLayer, BatchGetImage, BatchCheckLayerAvailability`.
Consequence: images (and any baked secrets) readable by anyone with the registry URI.
Fix: delete the repository policy. Effort: 2 min.

### F7 — S3 bucket open to all AuthenticatedUsers (CONFIRMED, P1)
Evidence (get-bucket-policy, roqy-audit-canary-authusers): `Principal:"*"`, `s3:GetObject`, Condition `aws:PrincipalType=AuthenticatedUser`; policy-status `IsPublic: true`.
Consequence: "not public" but readable by every AWS account holder (Dow Jones 2026 pattern, 2.2M customers).
Fix: remove the AuthUsers statement. Effort: 5 min.

### F8 — Lambda Function URL with AuthType NONE (CONFIRMED, P1)
Evidence (get-function-url-config canary-public-fn): `AuthType: NONE`, public lambda-url endpoint `https://5uedv22wvhuokswzmrkewjikxy0eazoa.lambda-url.eu-central-1.on.aws/`.
Consequence: unauthenticated public invoke endpoint, invisible in SG/ALB audits.
Fix: set AuthType AWS_IAM or delete the URL config. Effort: 2 min.

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
- not_applicable: W9/W18 EKS — no clusters exist.
- not_applicable: W15/W28/W35/W42 — no EC2 instances, SSM sessions, ECS tasks, or ALBs exist.
- not_applicable: W16 — account is not a member of an Organization (AWSOrganizationsNotInUseException).
- not_applicable: W19/W20/W21 — no self-owned AMIs, no RDS instances, no ACM certificates.
- not_applicable: W22 — auditor lacks Cost Explorer access (AccessDeniedException on GetReservationUtilization).
- not_applicable: W23 — no Bedrock or LLM spend surface found in the account.
- not_applicable: W39 — no public build artifacts or websites in this account to scan.

## Checks that passed (evidence, no finding)
- W4 root MFA enabled (AccountMFAEnabled=1); W40 no root access keys (AccountAccessKeysPresent=0).
- W10/W31: all 9 role trust policies trust AWS services only (eks, lambda, ec2, autoscaling, support); no cross-account principals, no wildcard, no ExternalId risk.
- W24/W25: PassRole inline policy "test" scoped to eksClusterRole/eksNodeRole only; no NotAction statements; no wildcard PassRole.
- W26: KMS key policy is the standard Secrets Manager integration with kms:CallerAccount condition; secret has no resource policy; no external accounts.
- W27: no bucket notification configurations on any bucket.
- W3/W11: only IAM user is the fresh audit identity; key created 2026-11-03, active — no dormant users, no stale keys.
- W12 no EC2 key pairs. W13 Lambda LastModified 2026-11-04 matches deploy. W14 no VPC endpoints. W17 python3.12 runtime current.
- W36: SES in sandbox (ProductionAccessEnabled=false, 200/day quota) — no abuse surface.

## Notes
- Write-probe bucket `roqy-audit-write-probe-856114194841` was created by a prior canary run to verify the read-only identity (create succeeded). Read-only mandate forbids deleting it; account owner should remove it.
- Secret `canary/db-password` has RotationEnabled=false but was created 2026-11-03, under the 90-day threshold — note only, not a finding.

## Execution order (one window)
1. F5 account PAB first, then F1 + F7 bucket policies — PAB first so fixes stick.
2. F2 snapshot permission removal.
3. F6 ECR policy delete, F8 Lambda URL auth, F11 SG rule removal.
4. F3 CloudTrail + F4 budget + F9 Config/GuardDuty + F10 EBS encryption default.
5. Cleanup: delete write-probe bucket.
