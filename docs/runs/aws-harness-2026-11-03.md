# Live Infra Audit — AWS <canary-account> (canary), 2026-11-03

Region eu-central-1. Identity: arn:aws:<audit-identity-arn>. Read-only run; one write probe (F12) disclosed below. Raw output: raw/recon.txt, raw/checks.txt, raw/checks2.txt.

## Inventory

| Resource | Count | Detail |
|---|---|---|
| IAM users | 1 | roqy-audit (audit identity, created 2026-11-03) |
| IAM roles | 8 | 6 AWS service roles + eksClusterRole + eksNodeRole |
| S3 buckets | 2 | roqy-audit-canary-authusers, roqy-audit-canary-openai-credentials |
| EC2 instances | 0 | none |
| Security groups | 2 | default, audit-canary-open-ssh |
| Snapshots | 1 | snap-089f51e581a18f555 (canary snapshot, 1 GB) |
| Secrets Manager | 1 | canary/db-password |
| KMS keys | 1 | Secrets Manager auto key |
| EKS / Lambda / ECR / RDS / ACM / VPC endpoints / key pairs | 0 | none |

## Findings

### F1 — S3 bucket open to every AWS account (AuthenticatedUsers grant) (CONFIRMED, P1)
Evidence: `get-bucket-policy-status` on roqy-audit-canary-authusers → `"IsPublic": true`. Policy: `Principal: *`, `Action: s3:GetObject`, `Condition aws:PrincipalType: AuthenticatedUser`. Account PAB all false (F8), so nothing blocks it.
Consequence: any AWS account holder can read every object; "not public" is an illusion. Dow Jones 2026 precedent (2.2M customers via this exact grant).
Fix: delete the policy statement; set account-level PAB all true. Effort: 15 min.
Note: bucket currently holds no objects (list empty), so exposure is latent, not active — hence P1, not P0.

### F2 — S3 bucket with global anonymous read AND write (CONFIRMED, P0)
Evidence: roqy-audit-canary-openai-credentials policy: `Principal: *`, `Action: ["s3:GetObject","s3:PutObject"]`, Resource `.../*`. `get-bucket-policy-status` → `"IsPublic": true`. Anonymous list returns AccessDenied (list not granted), but object-level Get/Put is granted to the world.
Consequence: anyone on the internet can plant files (malware hosting, phishing) and read anything written there. LA Times 2018 / Twilio 2020 / PREMINT 2022 pattern. Bucket name contains "openai-credentials" — attackers grep AI naming to find credential buckets fast (Sysdig 2026, W41).
Fix: delete the bucket policy; enable account PAB. Effort: 15 min.

### F3 — Public SSH security group with no instances (CONFIRMED, P1)
Evidence: sg-0d54fdcc2e24687bd "audit-canary-open-ssh": tcp 22, `CidrIp: 0.0.0.0/0`.
Consequence: any future instance attached to this SG gets password-brute-force surface from the whole internet. Latent today (0 instances) — P1.
Fix: restrict to a bastion/office CIDR or delete the SG. Effort: 10 min.

### F4 — EC2 snapshot shared to Group "all", unencrypted (CONFIRMED, P1)
Evidence: `describe-snapshot-attribute` snap-089f51e581a18f555 → `CreateVolumePermissions: [{"Group": "all"}]`; `Encrypted: false`.
Consequence: any AWS account can copy the full disk. Imperva 2019 / DNC 2016 pattern.
Fix: remove createVolumePermission group all; encrypt future volumes (see F9). Effort: 10 min.

### F5 — No CloudTrail (CONFIRMED, P1)
Evidence: `aws cloudtrail describe-trails` → `"trailList": []`.
Consequence: zero change history; an attacker with console/API access leaves no trace.
Fix: one multi-region trail to a dedicated bucket. Effort: 30 min.

### F6 — No budget alerts (CONFIRMED, P1)
Evidence: `aws budgets describe-budgets --account-id <canary-account>` → empty output.
Consequence: a leaked key or crypto-mining incident bills silently.
Fix: one $-threshold budget with email alert. Effort: 15 min.

### F7 — No Config recorder, no GuardDuty (CONFIRMED, P2)
Evidence: `describe-configuration-recorders` → `[]`; `guardduty list-detectors` → `[]`.
Consequence: no drift detection, no threat detection.
Fix: enable GuardDuty detector + Config recorder. Effort: 1 h.

### F8 — Account-level S3 Public Access Block all false (CONFIRMED, P2)
Evidence: `get-public-access-block` → BlockPublicAcls/IgnorePublicAcls/BlockPublicPolicy/RestrictPublicBuckets all `false`.
Consequence: no guardrail; any future bucket policy can go public unopposed (enables F1/F2).
Fix: put-public-access-block all true. Effort: 5 min.

### F9 — EBS encryption by default disabled (CONFIRMED, P2)
Evidence: `get-ebs-encryption-by-default` → `"EbsEncryptionByDefault": false`.
Consequence: every future volume born unencrypted (see F4).
Fix: `enable-ebs-encryption-by-default`. Effort: 5 min.

### F10 — Audit identity can write (write probe succeeded) (CONFIRMED, P2)
Evidence: `create-bucket <write-probe-bucket>` returned success (Location header). Per skill lesson, the probe should return AccessDenied for a read-only identity.
Consequence: the audit identity has S3 write permissions; audit scope is larger than intended. Side effect disclosed: the probe bucket was created and left in place (read-only mandate — no deletes). Remove it manually.
Fix: strip write permissions from roqy-audit; delete the probe bucket. Effort: 10 min.

### F11 — Secret without rotation (REJECTED)
Evidence: canary/db-password, `RotationEnabled` absent in `describe-secret`, created 2026-11-03 (today).
Why rejected: rule fires only on secrets older than 90 days. No concrete consequence today.

### F12 — Root account hygiene (REJECTED)
Evidence: `AccountMFAEnabled: 1`, `AccountAccessKeysPresent: 0`, `AccountPasswordPresent: 1`.
Why rejected: root MFA on, no root keys. Password presence alone is not a finding.

### F13 — IAM trust policies (REJECTED)
Evidence: all 8 roles trust only AWS service principals (eks, ec2, autoscaling, support, etc.). No cross-account principals, no wildcard, no missing ExternalId risk, no PassRole-on-* policies found.
Why rejected: no persistence pattern present.

### F14 — SES abuse surface (REJECTED)
Evidence: `sesv2 get-account` → `ProductionAccessEnabled: false`, Max24HourSend 200.
Why rejected: sandbox mode, negligible send quota.

### F15 — KMS cross-account exposure (REJECTED)
Evidence: key policy is the standard Secrets Manager auto-generated policy; every external-facing statement carries `kms:CallerAccount: <canary-account>` conditions.
Why rejected: no external account access.

## not_applicable lines

- not_applicable: W9/W18 EKS checks — no EKS clusters exist.
- not_applicable: W17/W20 Lambda/RDS EOL — no Lambda functions, no RDS instances.
- not_applicable: W21 TLS horizon — no ACM certificates.
- not_applicable: W22 RI/Savings Plans — none exist.
- not_applicable: W23 Bedrock spend guard — no Bedrock usage surface found in the account.
- not_applicable: W16 SCP coverage — account is not a member of an organization (AWSOrganizationsNotInUseException); SCPs cannot exist.
- not_applicable: W39 public build artifacts — no public endpoints or build artifacts in scope for this account.

## Execution order (one change window)

1. S3: account PAB all true + delete both bucket policies (F8, F1, F2).
2. EC2: remove snapshot public permission, restrict/delete open SSH SG, enable EBS default encryption (F4, F3, F9).
3. Detection: CloudTrail multi-region trail, budget alert, GuardDuty + Config (F5, F6, F7).
4. Cleanup: strip roqy-audit write perms, delete probe bucket (F10).
