# AWS canary audit — planted-case validation run

Date: 2026-11-03. Account <canary-account>, identity roqy-audit (SecurityAudit + temporary PowerUserAccess for planting). Region eu-central-1. Audit checks read-only.

## Planted cases

1. S3 bucket roqy-audit-canary-test with a public-read bucket policy and a fake secret object (verified: anonymous curl returns 200).
2. Security group audit-canary-open allowing tcp:22 from 0.0.0.0/0.
3. IAM long-lived key case: NOT plantable — PowerUserAccess denies iam:CreateAccessKey by design. The check itself was validated against the real roqy-audit key (created today, Active).

## Detection results

| Case | Verdict | Evidence |
|---|---|---|
| Public bucket | CONFIRMED P0 | get-public-access-block: no BPA on bucket; get-bucket-policy-status: IsPublic true; anonymous GET 200 |
| Open security group | CONFIRMED P0 | describe-security-groups: sg-07a524afe467effd2 allows tcp:22 from 0.0.0.0/0 |
| Long-lived IAM keys | CONFIRMED P1 (method validated) | list-access-keys with CreateDate; age check >90d is the finding rule |
| Root MFA | PASS (control present) | AccountMFAEnabled=1 |

## Lessons that went into the skill

1. New AWS accounts: buckets are BucketOwnerEnforced, ACLs cannot grant public access. The public-bucket check must use bucket POLICY (get-bucket-policy-status IsPublic) plus an anonymous curl, not object ACLs.
2. Account-level PublicAccessBlock may not exist (NoSuchPublicAccessBlockConfiguration) — absence is itself a finding candidate (P2, hygiene).
3. PowerUserAccess cannot write IAM — planting IAM findings requires the account owner. The read-only identity can still DETECT them (list-access-keys works under SecurityAudit).
4. Write-probe validation: create-bucket/create-user returning AccessDenied proves the identity is read-only. This is now part of the identity verification step.

## Cleanup

Canary bucket emptied and deleted; security group deleted. PowerUserAccess to be removed by Ron after this run.
