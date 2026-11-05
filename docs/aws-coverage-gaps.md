# AWS coverage gaps vs CHECKS-AWS.md (final-pr) — from breach-pattern research

## MISSING
1. GitHub Actions/OIDC/SAML federated trust without :sub condition or org-wide wildcard sub (iam list-open-id-connect-providers, list-roles). P0.
2. S3 ransomware resilience (Codefinger SSE-C): get-bucket-encryption BlockedEncryptionTypes, get-bucket-versioning, get-object-lock-configuration, get-bucket-lifecycle-configuration; AWS Backup list-backup-vaults/describe-backup-vault (Locked). P1/P0.
3. Dangling DNS / subdomain takeover: route53 list-resource-record-sets; CNAMEs to s3-website/elasticbeanstalk/cloudfront of non-existent resources; A records not in ec2 describe-addresses. P1.
4. Name-confusion supply chain: ec2 get-allowed-images-settings, owners of running AMIs, IaC aws_ami without owners; s3api head-bucket --expected-bucket-owner for buckets referenced in code. P1.
5. CI/CD into AWS (CodeBreach): codebuild batch-get-projects webhook filterGroups without ^/$ anchors, service role, list-source-credentials. P1.
6. Secrets in compute config & unauth endpoints: Lambda env var NAMES only, ECS task def env names, user-data names only; lambda get-policy Principal *; API Gateway authorizationType NONE, apigatewayv2 routes. P1.
7. Cognito: AllowAdminCreateUserOnly=false, client-writable email, identity pools AllowUnauthenticatedIdentities + unauth role perms. P1.
## PARTIAL
- Leaked access keys show up as attachments of the AWSCompromisedKeyQuarantine policies V2 and V3 (iam list-entities-for-policy). P0 if hit. Also check the credential report.
- Human identities: IAM users password_enabled without mfa_active; sso-admin list-instances; password policy.
- IMDS (W15): HttpPutResponseHopLimit=1 on EKS nodes, ec2 get-instance-metadata-defaults, launch template MetadataOptions.
- IAM privesc: CreatePolicyVersion, Attach/PutUserPolicy, Attach/PutRolePolicy, UpdateAssumeRolePolicy, CreateAccessKey/CreateLoginProfile on others, lambda:UpdateFunctionCode on admin-role functions, ssm:SendCommand; Access Analyzer list-findings-v2.
- Snapshots/AMIs (W34): public AMIs, describe-db-cluster-snapshot-attributes, get-snapshot-block-public-access-state, get-image-block-public-access-state.
- LLMjacking (W23): get-anomaly-monitors + get-anomaly-subscriptions; bedrock get-model-invocation-logging-configuration per region.
- EKS (W9/W18): authenticationMode, bootstrapClusterCreatorAdminPermissions, publicAccessCidrs, list-access-entries, list-associated-access-policies, aws-auth system:masters (with --context), pod identity associations.
- Logging: cloudtrail get-trail-status, get-event-selectors, log file validation; GuardDuty all regions + list-findings high sev; account get-alternate-contact SECURITY.
- Region loop over ec2 describe-regions for SES, GuardDuty, Bedrock, EC2.
- W2 IPv6 CidrIpv6 fix. W40 Truffle stat correction: 10,616 keys rechecked, 88% still valid; 526 root keys within 768 corporate full-admin keys.
- Read-only rule: never pull secret values (env names only, no full user-data, exclude Cognito ClientSecret via --query).
