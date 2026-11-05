#!/usr/bin/env python3
"""Source of truth for EXPECTED-FINDINGS.yaml. Edit here, re-run, commit both."""
import yaml, os

C = {
 "c1": "Leaked long-lived access keys", "c2": "SSRF / IMDSv1", "c3": "IAM privilege escalation",
 "c4": "Public / cross-account S3", "c5": "Public or shared snapshots & AMIs",
 "c6": "S3 ransomware & destruction (SSE-C, lifecycle, backups)", "c7": "Open federated trust (GitHub OIDC)",
 "c8": "Third-party / confused deputy", "c9": "LLMjacking (Bedrock)", "c10": "SES abuse",
 "c11": "Subdomain takeover (dangling DNS)", "c12": "Name confusion (AMIs, buckets)",
 "c13": "CI/CD into AWS (CodeBuild)", "c14": "Secrets in compute config & unauth endpoints",
 "c15": "EKS identities", "c16": "Cognito misconfiguration", "c17": "Human identity theft",
 "c18": "Logging & detection blind spots", "x-net": "Network exposure (supporting)",
 "x-data": "Data protection hygiene (supporting)",
 "c19": "Terraform state & backend", "c20": "IaC drift (code != cloud)", "c21": "IaC supply chain",
 "c22": "CI/CD pipeline into the cloud (GitHub Actions)", "c23": "Kubernetes workloads & RBAC",
 "c24": "Helm releases", "c25": "Cross-layer attack chains",
 "c26": "Container & dependency supply chain", "c27": "AI agent supply chain (skills/MCP)",
}

P = []
def p(id, cat, resource, checks, sev, detect, finding_if, kind="plant", requires=(), guarded=False, notes=""):
    P.append(dict(id=id, category=cat, category_name=C[cat], kind=kind, resource=resource,
                  expected_check_ids=list(checks), expected_severity=sev,
                  enabled_by_default=all(r in DEFAULT_ON for r in requires),
                  requires=list(requires), guarded_by_boundary=guarded,
                  detect_read_only=list(detect), finding_if=finding_if, notes=notes))

DEFAULT_ON = {"envelope", "second_region", "instance", "no_weak_trail", "dns", "kms_deletion", "absence_intact", "rds", "eks"}

# ---------------- c1 / c17 identities ----------------
p("iam-quarantined-user", "c1", "roqy-lab-leaked-ci-user", ["NEW-KEY-QUARANTINE"], "P0",
  ["aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2",
   "aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV3"],
  "Any user/role attached to AWSCompromisedKeyQuarantine* = AWS saw this key leaked publicly (quarantine is not revocation).")
p("iam-user-unused-key", "c1", "roqy-lab-console-user", ["W3", "W11"], "P2",
  ["aws iam list-users", "aws iam list-access-keys --user-name roqy-lab-console-user",
   "aws iam get-access-key-last-used --access-key-id <id>"],
  "Active long-lived key never used (LastUsedDate absent) on an admin user. W3 >90d age rule will NOT fire on a fresh lab; W11/never-used must.",
  guarded=True)
p("iam-console-no-mfa", "c17", "roqy-lab-console-user", ["NEW-CONSOLE-NO-MFA"], "P1",
  ["aws iam generate-credential-report", "aws iam get-credential-report --query Content --output text",
   "aws iam list-mfa-devices --user-name roqy-lab-console-user"],
  "password_enabled=true and mfa_active=false (credential report CSV, base64). User also has AdministratorAccess.",
  guarded=True)
p("iam-no-password-policy", "c17", "account", ["NEW-PASSWORD-POLICY"], "P2",
  ["aws iam get-account-password-policy"], "NoSuchEntity = no password policy.",
  kind="absence", requires=["absence_intact"])
p("sso-not-used", "c17", "account", ["NEW-SSO-ABSENT"], "P3",
  ["aws sso-admin list-instances"], "No IAM Identity Center instance while IAM users have console passwords.",
  kind="absence", requires=["absence_intact"])

# ---------------- c2 IMDS ----------------
p("ec2-imdsv1-instance", "c2", "roqy-lab-imdsv1", ["W15"], "P1",
  ["aws ec2 describe-instances --filters Name=tag:roqy-lab,Values=true --query 'Reservations[].Instances[].{i:InstanceId,t:MetadataOptions.HttpTokens,h:MetadataOptions.HttpPutResponseHopLimit,s:State.Name}'"],
  "HttpTokens=optional (IMDSv1). HopLimit=2 makes it reachable from containers. Instance carries an Action:* role.",
  requires=["instance"])
p("ec2-imdsv1-launch-template", "c2", "roqy-lab-imdsv1", ["W15", "NEW-IMDS-LAUNCH-TEMPLATE"], "P2",
  ["aws ec2 describe-launch-templates", "aws ec2 describe-launch-template-versions --launch-template-name roqy-lab-imdsv1 --versions '$Latest' --query 'LaunchTemplateVersions[].LaunchTemplateData.MetadataOptions'"],
  "Launch template MetadataOptions.HttpTokens=optional: every future instance/ASG member is born IMDSv1.")
p("ec2-imds-account-default-unset", "c2", "account", ["NEW-IMDS-ACCOUNT-DEFAULT"], "P3",
  ["aws ec2 get-instance-metadata-defaults"], "AccountLevel.HttpTokens not 'required'.",
  kind="absence", requires=["absence_intact"])

# ---------------- network ----------------
p("sg-open-admin-ports", "x-net", "roqy-lab-legacy-admin", ["W2"], "P1",
  ["aws ec2 describe-security-groups --filters Name=group-name,Values=roqy-lab-legacy-admin",
   "aws ec2 describe-network-interfaces --filters Name=group-id,Values=<sg>"],
  "22/3389/6379/9200 open to 0.0.0.0/0 AND ::/0. With instance stopped/none => needs_validation (no public ENI), still reported.")
p("sg-all-traffic", "x-net", "roqy-lab-legacy-admin", ["W2"], "P1",
  ["aws ec2 describe-security-groups --query \"SecurityGroups[?IpPermissions[?IpProtocol=='-1']].GroupId\""],
  "IpProtocol -1 from 0.0.0.0/0 (all ports). W2 query filters IpProtocol==tcp and MISSES this today.")
p("sg-ipv6-open", "x-net", "roqy-lab-ipv6-bastion", ["W2"], "P1",
  ["aws ec2 describe-security-groups --query \"SecurityGroups[?IpPermissions[?Ipv6Ranges[?CidrIpv6=='::/0']]].GroupId\""],
  "IPv6-only ::/0 on 22. Regression test for W2 querying Ipv6Ranges[].CidrIp instead of CidrIpv6.")

# ---------------- c3 privesc ----------------
p("iam-privesc-user", "c3", "roqy-lab-intern", ["NEW-IAM-PRIVESC", "W24"], "P1",
  ["aws iam list-user-policies --user-name roqy-lab-intern", "aws iam get-user-policy --user-name roqy-lab-intern --policy-name roqy-lab-intern-dev",
   "aws iam get-account-authorization-details --filter User"],
  "iam:CreatePolicyVersion, iam:PassRole+lambda:CreateFunction on *, iam:UpdateAssumeRolePolicy, AttachUserPolicy, CreateAccessKey/CreateLoginProfile on *, ssm:SendCommand.")
p("iam-wildcard-admin-role", "c3", "roqy-lab-app-server", ["NEW-WILDCARD-ADMIN"], "P1",
  ["aws iam get-role-policy --role-name roqy-lab-app-server --policy-name everything"],
  "Inline Allow Action * Resource * on an EC2 instance-profile role (and that role sits behind IMDSv1).")
p("iam-notaction-policy", "c3", "roqy-lab-everything-but-iam", ["W25"], "P2",
  ["aws iam list-policies --scope Local", "aws iam get-policy-version --policy-arn <arn> --version-id <v>"],
  "Allow NotAction [iam:*, organizations:*] Resource * = effectively admin minus IAM.")

# ---------------- c4 S3 ----------------
p("s3-ai-named-bucket", "c4", "roqy-lab-llm-rag-data", ["W41"], "P3",
  ["aws s3api list-buckets --query 'Buckets[].Name'"], "Bucket name matches llm|rag|ai-|model pattern.")
p("s3-cross-account-grant", "c4", "roqy-lab-llm-rag-data", ["NEW-S3-CROSS-ACCOUNT", "W10"], "P1",
  ["aws s3api get-bucket-policy --bucket <b>"], "Bucket policy grants Get/Put to a foreign account root.",
  requires=["foreign_account"])
p("s3-public-read-policy", "c4", "roqy-lab-llm-rag-data", ["W1"], "P0",
  ["aws s3api get-bucket-policy-status --bucket <b>", "aws s3api get-bucket-policy --bucket <b>"],
  "IsPublic=true; Principal * s3:GetObject.", requires=["allow_public"])
p("s3-public-write", "c4", "roqy-lab-llm-rag-data", ["W33"], "P0",
  ["aws s3api get-bucket-policy --bucket <b>"], "Principal * s3:PutObject.", requires=["allow_public"])
p("s3-account-bpa", "c4", "account", ["W5"], "P2",
  ["aws s3control get-public-access-block --account-id <id>"],
  "NoSuchPublicAccessBlockConfiguration. The lab NEVER changes account BPA; active only if the sandbox never set it.",
  kind="absence", requires=["absence_intact", "account_bpa_unset"],
  notes="Sandbox 856114194841 turned account BPA on (2026-11-04 canary cleanup): pass --enable account_bpa_unset only on an account without it.")

# ---------------- c6 ransomware ----------------
p("s3-no-versioning-objectlock", "c6", "roqy-lab-customer-uploads", ["NEW-S3-RANSOMWARE"], "P1",
  ["aws s3api get-bucket-versioning --bucket <b>", "aws s3api get-object-lock-configuration --bucket <b>"],
  "Versioning not Enabled and no Object Lock = one DeleteObjects call is permanent.")
p("s3-sse-c-allowed", "c6", "roqy-lab-customer-uploads", ["NEW-S3-SSEC"], "P1",
  ["aws s3api get-bucket-encryption --bucket <b> --query 'ServerSideEncryptionConfiguration.Rules[].BlockedEncryptionTypes'"],
  "BlockedEncryptionTypes does not contain SSE-C (lab sets NONE explicitly) = Codefinger-style re-encryption ransom possible.")
p("s3-lifecycle-expiration", "c6", "roqy-lab-customer-uploads", ["NEW-S3-LIFECYCLE-EXPIRY"], "P2",
  ["aws s3api get-bucket-lifecycle-configuration --bucket <b>"],
  "Expiration Days=1 on whole bucket (empty filter), rule named 'cleanup-tmp'. Attackers add this to destroy data quietly.")
p("backup-no-locked-vault", "c6", "account", ["NEW-BACKUP-VAULT-LOCK"], "P2",
  ["aws backup list-backup-vaults --query 'BackupVaultList[].{n:BackupVaultName,l:Locked}'"],
  "No vault with Locked=true = backups deletable with the same stolen admin key.",
  kind="absence", requires=["absence_intact"])

# ---------------- c5 snapshots/AMIs ----------------
p("ebs-unencrypted-snapshot", "c5", "roqy-lab-prod-db-backup", ["NEW-UNENCRYPTED-SNAPSHOT"], "P2",
  ["aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?Encrypted==`false`].SnapshotId'"],
  "Unencrypted snapshot named like a DB backup (shareable publicly; encrypted ones cannot be).")
p("ebs-snapshot-public", "c5", "roqy-lab-prod-db-backup", ["W34"], "P0",
  ["aws ec2 describe-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission"],
  "CreateVolumePermissions contains Group=all.", requires=["allow_public"])
p("ebs-snapshot-shared-foreign", "c5", "roqy-lab-prod-db-backup", ["W34"], "P1",
  ["aws ec2 describe-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission"],
  "CreateVolumePermissions contains a foreign UserId.", requires=["foreign_account"])
p("ami-public", "c5", "roqy-lab-golden-image", ["NEW-PUBLIC-AMI", "W34"], "P0",
  ["aws ec2 describe-images --owners self --query 'Images[].{id:ImageId,p:Public}'",
   "aws ec2 describe-image-attribute --image-id <ami> --attribute launchPermission"],
  "Public=true / launchPermission Group=all.", requires=["allow_public"])
p("ebs-default-encryption-off", "c5", "account", ["W32"], "P2",
  ["aws ec2 get-ebs-encryption-by-default"], "EbsEncryptionByDefault=false.", kind="absence", requires=["absence_intact"])
p("snapshot-image-bpa-off", "c5", "account", ["NEW-SNAPSHOT-BPA"], "P3",
  ["aws ec2 get-snapshot-block-public-access-state", "aws ec2 get-image-block-public-access-state"],
  "State unblocked = nothing stops the next public share.", kind="absence", requires=["absence_intact"])

# ---------------- c7 / c8 trust ----------------
p("iam-github-oidc-no-sub", "c7", "roqy-lab-github-deploy", ["NEW-OIDC-NO-SUB"], "P0",
  ["aws iam list-open-id-connect-providers", "aws iam list-roles --query \"Roles[?contains(to_string(AssumeRolePolicyDocument),'token.actions.githubusercontent.com')].RoleName\"",
   "aws iam get-role --role-name roqy-lab-github-deploy --query Role.AssumeRolePolicyDocument"],
  "Trust on token.actions.githubusercontent.com with aud only and no :sub condition (or sub=*) = ANY GitHub repo can assume. Role has PowerUserAccess.",
  guarded=True)
p("iam-cross-account-no-externalid", "c8", "roqy-lab-vendor-integration", ["W31", "W10"], "P1",
  ["aws iam get-role --role-name roqy-lab-vendor-integration --query Role.AssumeRolePolicyDocument"],
  "AWS principal :root of another account with no sts:ExternalId condition. Without foreign_account_id it trusts the sandbox root itself (still no ExternalId) - auditor may downgrade to P3.",
  guarded=True)
p("iam-trust-wildcard-principal", "c8", "roqy-lab-vendor-integration", ["W10"], "P0",
  ["aws iam get-role --role-name roqy-lab-vendor-integration --query Role.AssumeRolePolicyDocument"],
  "Principal AWS * in a trust policy = any AWS account in the world.", requires=["allow_public"], guarded=True)

# ---------------- c9 LLMjacking ----------------
p("bedrock-logging-off", "c9", "account", ["W23", "NEW-BEDROCK-LOGGING"], "P2",
  ["aws bedrock get-model-invocation-logging-configuration --region eu-central-1",
   "aws bedrock get-model-invocation-logging-configuration --region us-east-1"],
  "No loggingConfig in any region = LLMjacking invisible.", kind="absence", requires=["absence_intact"])
p("ce-no-anomaly-monitor", "c9", "account", ["W23"], "P2",
  ["aws ce get-anomaly-monitors", "aws ce get-anomaly-subscriptions"],
  "No monitors/subscriptions = a stolen key's Bedrock bill is noticed on the invoice.", kind="absence", requires=["absence_intact"])
p("no-budgets", "c9", "account", ["W7"], "P2",
  ["aws budgets describe-budgets --account-id <id>"], "No budgets.", kind="absence", requires=["absence_intact"])

# ---------------- c10 SES ----------------
p("ses-domain-identity", "c10", "roqy-lab", ["W36"], "P3",
  ["aws sesv2 get-account", "aws sesv2 list-email-identities"],
  "Identity exists; account in sandbox (ProductionAccessEnabled=false) -> informational. Production access cannot be planted (needs AWS support).")

# ---------------- c11 DNS ----------------
p("r53-dangling-cname-s3", "c11", "assets.roqy-lab.internal", ["NEW-DANGLING-DNS"], "P1",
  ["aws route53 list-hosted-zones", "aws route53 list-resource-record-sets --hosted-zone-id <zone>",
   "aws s3api head-bucket --bucket <name-from-cname>"],
  "CNAME -> <bucket>.s3-website.<region>.amazonaws.com where the bucket does not exist (head-bucket 404). Private zone by default.",
  requires=["dns"])
p("r53-dangling-cname-eb", "c11", "app.roqy-lab.internal", ["NEW-DANGLING-DNS"], "P1",
  ["aws route53 list-resource-record-sets --hosted-zone-id <zone>",
   "aws elasticbeanstalk check-dns-availability --cname-prefix <prefix>"],
  "CNAME -> <prefix>.<region>.elasticbeanstalk.com and check-dns-availability says Available=true (anyone can claim it).",
  requires=["dns"])

# ---------------- c12 name confusion ----------------
p("ec2-allowed-amis-off", "c12", "account", ["NEW-ALLOWED-AMIS"], "P3",
  ["aws ec2 get-allowed-images-settings"], "State disabled = whoAMI name-confusion AMIs can be launched.",
  kind="absence", requires=["absence_intact"],
  notes="Repo-side twin: iac-samples/whoami.tf.example (aws_ami data source with name filter and no owners) for infra-readiness-audit.")

# ---------------- c13 CI/CD ----------------
p("codebuild-privileged-plaintext-env", "c13", "roqy-lab-deploy", ["NEW-CODEBUILD"], "P1",
  ["aws codebuild list-projects", "aws codebuild batch-get-projects --names roqy-lab-deploy --query 'projects[].{p:environment.privilegedMode,e:environment.environmentVariables[].{n:name,t:type},r:serviceRole}'"],
  "privilegedMode=true, PLAINTEXT env named GITHUB_TOKEN/AWS_SECRET_ACCESS_KEY (report NAMES only), service role can PassRole+CreateRole+AttachRolePolicy.")
p("codebuild-unanchored-webhook", "c13", "roqy-lab-pr-builder", ["NEW-CODEBUILD-WEBHOOK"], "P1",
  ["aws codebuild batch-get-projects --names roqy-lab-pr-builder --query 'projects[].webhook.filterGroups'",
   "aws codebuild list-source-credentials"],
  "ACTOR_ACCOUNT_ID pattern without ^...$ anchors (CodeBreach 2026).", requires=["codebuild_webhook"])

# ---------------- c14 secrets / unauth endpoints ----------------
p("lambda-secret-env", "c14", "roqy-lab-payments-webhook", ["NEW-LAMBDA-ENV-SECRETS"], "P1",
  ["aws lambda list-functions --query 'Functions[].{f:FunctionName,env:keys(Environment.Variables||`{}`)}'"],
  "Env var NAMES like STRIPE_SECRET_KEY / LEGACY_AWS_SECRET_KEY / DB_PASSWORD. Report names only, never values.")
p("lambda-policy-principal-star", "c14", "roqy-lab-payments-webhook", ["NEW-LAMBDA-PUBLIC-POLICY"], "P1",
  ["aws lambda get-policy --function-name roqy-lab-payments-webhook"],
  "Statement with Principal * (lambda:InvokeFunction) and no SourceAccount/SourceArn condition.")
p("lambda-url-auth-none", "c14", "roqy-lab-payments-webhook", ["W43"], "P1",
  ["aws lambda list-function-url-configs --function-name roqy-lab-payments-webhook"], "AuthType NONE.",
  requires=["allow_public"])
p("apigw-route-no-auth", "c14", "roqy-lab-public-api", ["NEW-APIGW-NO-AUTH"], "P2",
  ["aws apigatewayv2 get-apis", "aws apigatewayv2 get-routes --api-id <id> --query 'Items[].{r:RouteKey,a:AuthorizationType}'"],
  "Route 'POST /admin/refund' AuthorizationType NONE (name implies privileged action).")
p("ecs-taskdef-secret-env", "c14", "roqy-lab-billing-worker", ["NEW-ECS-ENV-SECRETS", "W35"], "P1",
  ["aws ecs list-task-definitions", "aws ecs describe-task-definition --task-definition roqy-lab-billing-worker --query 'taskDefinition.containerDefinitions[].environment[].name'"],
  "Plaintext environment NAMES DB_PASSWORD/GITHUB_TOKEN/AWS_SECRET_ACCESS_KEY (should be secrets: from SSM/SecretsManager).")
p("ssm-string-password", "c14", "/roqy-lab/prod/db_master_password", ["NEW-SSM-PLAINTEXT"], "P2",
  ["aws ssm describe-parameters --query \"Parameters[?Type=='String'].Name\""],
  "Type String (not SecureString) with name containing password/secret/key. Never call get-parameter.")
p("ec2-userdata-secret", "c14", "roqy-lab-imdsv1", ["NEW-USERDATA-SECRETS"], "P2",
  ["aws ec2 describe-launch-template-versions --launch-template-name roqy-lab-imdsv1 --versions '$Latest' --query 'LaunchTemplateVersions[].LaunchTemplateData.UserData'"],
  "User-data contains DB_PASSWORD/STRIPE_SECRET_KEY assignments. Decode locally, report NAMES only, never echo values.")
p("secretsmanager-no-rotation", "c14", "roqy-lab/prod/stripe", ["W37"], "P3",
  ["aws secretsmanager list-secrets --query 'SecretList[].{n:Name,r:RotationEnabled}'"],
  "RotationEnabled false. Age <90d on a fresh lab, so W37 may correctly stay quiet (scored as informational).",
  requires=["secrets_manager"])

# ---------------- c15 EKS ----------------
p("eks-public-endpoint", "c15", "roqy-lab-eks", ["W9"], "P1",
  ["aws eks describe-cluster --name roqy-lab-eks --query 'cluster.resourcesVpcConfig.{pub:endpointPublicAccess,cidrs:publicAccessCidrs}'"],
  "endpointPublicAccess=true with 0.0.0.0/0.", requires=["eks"])
p("eks-creator-admin", "c15", "roqy-lab-eks", ["NEW-EKS-AUTH"], "P2",
  ["aws eks describe-cluster --name roqy-lab-eks --query 'cluster.accessConfig'"],
  "bootstrapClusterCreatorAdminPermissions=true and authenticationMode still includes CONFIG_MAP (aws-auth) = invisible standing cluster-admin.",
  requires=["eks"])
p("eks-broad-access-entry", "c15", "roqy-lab-eks", ["NEW-EKS-AUTH"], "P1",
  ["aws eks list-access-entries --cluster-name roqy-lab-eks",
   "aws eks list-associated-access-policies --cluster-name roqy-lab-eks --principal-arn <arn>"],
  "Non-operator IAM user (roqy-lab-intern, itself a privesc user) has AmazonEKSClusterAdminPolicy at cluster scope.",
  requires=["eks"])
p("eks-old-version", "c15", "roqy-lab-eks", ["W18"], "P2",
  ["aws eks describe-cluster --name roqy-lab-eks --query 'cluster.version'"],
  "Version in extended support. Only planted when eks_version is set to an old version (costs ~$365/mo extra).",
  requires=["eks", "eks_old_version"])

# ---------------- c16 Cognito ----------------
p("cognito-self-signup", "c16", "roqy-lab-customers", ["NEW-COGNITO-SIGNUP"], "P2",
  ["aws cognito-idp list-user-pools --max-results 60", "aws cognito-idp describe-user-pool --user-pool-id <id> --query 'UserPool.AdminCreateUserConfig'"],
  "AllowAdminCreateUserOnly=false (public sign-up).")
p("cognito-email-writable", "c16", "roqy-lab-spa", ["NEW-COGNITO-ATTR"], "P1",
  ["aws cognito-idp list-user-pool-clients --user-pool-id <id>", "aws cognito-idp describe-user-pool-client --user-pool-id <id> --client-id <cid> --query 'UserPoolClient.WriteAttributes'"],
  "Client may write email and custom:role (self-promoted claims / Flickr-style takeover). Exclude ClientSecret from output.")
p("cognito-unauth-identity-s3", "c16", "roqy_lab_guest_pool", ["NEW-COGNITO-UNAUTH"], "P0",
  ["aws cognito-identity list-identity-pools --max-results 60", "aws cognito-identity describe-identity-pool --identity-pool-id <id>",
   "aws cognito-identity get-identity-pool-roles --identity-pool-id <id>", "aws iam get-role-policy --role-name roqy-lab-cognito-guest --policy-name guest-s3"],
  "AllowUnauthenticatedIdentities=true and unauth role grants s3:* on * = anonymous internet user gets S3 admin.", guarded=True)

# ---------------- c18 logging ----------------
p("cloudtrail-absent", "c18", "account", ["W6"], "P1",
  ["aws cloudtrail describe-trails"], "Zero trails.", kind="absence", requires=["no_weak_trail", "absence_intact"])
p("cloudtrail-single-region-novalidation", "c18", "roqy-lab-trail", ["W29", "NEW-TRAIL-VALIDATION"], "P1",
  ["aws cloudtrail describe-trails --query 'trailList[].{n:Name,m:IsMultiRegionTrail,v:LogFileValidationEnabled,g:IncludeGlobalServiceEvents}'",
   "aws cloudtrail get-trail-status --name roqy-lab-trail", "aws cloudtrail get-event-selectors --trail-name roqy-lab-trail"],
  "IsMultiRegionTrail=false, LogFileValidationEnabled=false, no global events.", requires=["weak_trail"])
p("guardduty-off", "c18", "account", ["W8"], "P2",
  ["aws guardduty list-detectors --region eu-central-1", "aws guardduty list-detectors --region us-east-1"],
  "No detector in any region (loop over ec2 describe-regions).", kind="absence", requires=["absence_intact"])
p("config-off", "c18", "account", ["W8"], "P2",
  ["aws configservice describe-configuration-recorders"], "No recorder.", kind="absence", requires=["absence_intact"])
p("access-analyzer-off", "c18", "account", ["NEW-ACCESS-ANALYZER"], "P3",
  ["aws accessanalyzer list-analyzers"], "No analyzer = external access to KMS/S3/roles is not continuously flagged.",
  kind="absence", requires=["absence_intact"])
p("no-security-contact", "c18", "account", ["NEW-SECURITY-CONTACT"], "P3",
  ["aws account get-alternate-contact --alternate-contact-type SECURITY"],
  "ResourceNotFoundException = AWS abuse/leaked-key notices go only to the root email.", kind="absence", requires=["absence_intact"])
p("log-group-no-retention", "c18", "/aws/lambda/roqy-lab-payments-webhook", ["W45"], "P3",
  ["aws logs describe-log-groups --query 'logGroups[?retentionInDays==null].logGroupName'"], "retentionInDays null.")

# ---------------- KMS / ECR / SNS / SQS ----------------
p("kms-cross-account-policy", "x-data", "alias/roqy-lab-shared-data", ["W26"], "P1",
  ["aws kms list-keys", "aws kms get-key-policy --key-id <id> --policy-name default"],
  "Key policy grants kms:Decrypt to a foreign account root.", requires=["foreign_account"])
p("kms-no-rotation", "x-data", "alias/roqy-lab-shared-data", ["NEW-KMS-ROTATION"], "P3",
  ["aws kms get-key-rotation-status --key-id <id>"], "KeyRotationEnabled=false on a customer managed key.")
p("kms-pending-deletion", "x-data", "alias/roqy-lab-prod-backups", ["NEW-KMS-PENDING-DELETION"], "P2",
  ["aws kms describe-key --key-id <id> --query 'KeyMetadata.{s:KeyState,d:DeletionDate}'"],
  "KeyState PendingDeletion on a key aliased 'prod-backups' = data becomes unrecoverable on DeletionDate (also a ransomware move).",
  requires=["kms_deletion"])
p("ecr-scan-off-mutable", "x-data", "roqy-lab/api", ["NEW-ECR-HYGIENE"], "P3",
  ["aws ecr describe-repositories --query 'repositories[].{n:repositoryName,m:imageTagMutability,s:imageScanningConfiguration.scanOnPush}'"],
  "MUTABLE tags + scanOnPush false.")
p("ecr-public-pull", "x-data", "roqy-lab/api", ["W30"], "P1",
  ["aws ecr get-repository-policy --repository-name roqy-lab/api"], "Principal * pull.", requires=["allow_public"])
p("sns-principal-star", "x-data", "roqy-lab-order-events", ["W44"], "P2",
  ["aws sns list-topics", "aws sns get-topic-attributes --topic-arn <arn> --query Attributes.Policy"],
  "Principal AWS * with SNS:Publish/Subscribe, no condition.")
p("sqs-principal-star", "x-data", "roqy-lab-jobs", ["W44"], "P2",
  ["aws sqs list-queues", "aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy"],
  "Principal * sqs:SendMessage, no condition.")
p("rds-public-unencrypted-old", "x-data", "roqy-lab-legacy-db", ["NEW-RDS-EXPOSURE", "W20"], "P1",
  ["aws rds describe-db-instances --query 'DBInstances[].{i:DBInstanceIdentifier,p:PubliclyAccessible,e:StorageEncrypted,v:EngineVersion}'"],
  "PubliclyAccessible=true, StorageEncrypted=false, BackupRetentionPeriod=0, DeletionProtection=false, oldest still-supported major (PG14, standard support ends 2027-02) - compare the RUNNING version to EOL dates, not offered versions. SG is VPC-only unless allow_public.",
  requires=["rds"])

# ---------------- second region ----------------
p("r2-open-sg", "x-net", "roqy-lab-r2-forgotten-ssh", ["W2"], "P2",
  ["aws ec2 describe-regions --query 'Regions[].RegionName'", "aws ec2 describe-security-groups --region us-east-1 --filters Name=group-name,Values=roqy-lab-r2-forgotten-ssh"],
  "SG 22 open v4+v6 in us-east-1. Detects that the audit loops regions. Unattached -> needs_validation.",
  requires=["second_region"])
p("r2-ssm-plaintext", "c14", "/roqy-lab-r2/legacy/api_secret_key", ["NEW-SSM-PLAINTEXT"], "P2",
  ["aws ssm describe-parameters --region us-east-1"], "String param named api_secret_key in the second region.",
  requires=["second_region"])

# =====================================================================================
# ENVELOPE extension (c19-c25): what Prowler / Security Hub do not see.
# Deployed by scripts/apply-envelope.sh. Repo-side plants live in client-repo/ (static scan).
# K8s/Helm plants need eks. Detect commands are read-only; kubectl/helm ALWAYS with explicit context.
# =====================================================================================
ENV = ["envelope"]; K8S = ["envelope", "eks"]
RO_K = "kubectl --context roqy-lab-audit-ro"
# ---- c19 state & backend ----
p("tf-state-no-versioning", "c19", "roqy-lab-client-tfstate", ["NEW-TF-STATE-VERSIONING"], "P1",
  ["grep -A8 'backend \"s3\"' client-repo/infra/*.tf", "aws s3api get-bucket-versioning --bucket <state bucket>"],
  "Bucket that holds *.tfstate has versioning off: one bad apply / delete / ransomware overwrite = state gone, no rollback.", requires=ENV)
p("tf-state-no-kms", "c19", "roqy-lab-client-tfstate", ["NEW-TF-STATE-ENCRYPTION"], "P2",
  ["aws s3api get-bucket-encryption --bucket <state bucket>", "aws s3api get-bucket-policy --bucket <state bucket>"],
  "Only the S3 default SSE-S3 (anyone with s3:GetObject reads plaintext), no SSE-KMS key gate, backend encrypt=false, no TLS-only deny.", requires=ENV)
p("tf-state-broad-read", "c19", "roqy-lab-client-tfstate", ["NEW-TF-STATE-ACCESS"], "P1",
  ["aws s3api get-bucket-policy --bucket <state bucket> --query Policy --output text"],
  "Allow Principal * limited only by aws:PrincipalAccount (or account :root) with GetObject/PutObject = every principal in the account reads (and rewrites) state.", requires=ENV)
p("tf-state-no-lock", "c19", "backend.tf", ["NEW-TF-STATE-LOCK"], "P2",
  ["grep -nE 'dynamodb_table|use_lockfile' client-repo/infra/backend.tf"],
  "S3 backend with neither use_lockfile=true (TF >=1.10) nor dynamodb_table: concurrent applies (CI + laptop) corrupt state.", requires=ENV)
p("tf-state-plaintext-secrets", "c19", "aws_ssm_parameter.db_password", ["NEW-TF-STATE-SECRETS"], "P1",
  ["static: resources whose secret attributes persist in state (aws_ssm_parameter.value, aws_db_instance.password, random_password, *_secret_version, outputs)",
   "aws s3api list-objects-v2 --bucket <state bucket> --query 'Contents[].Key'   # key names only, never GetObject"],
  "State contains the DB password in plaintext (sensitive=true only hides CLI output). Read-only role cannot GetObject -> status needs_validation unless the client shares a redacted `terraform show -json`.", requires=ENV)
p("tf-hardcoded-secret-default", "c19", "var.db_password", ["NEW-TF-HARDCODED-SECRET"], "P1",
  ["static: variable blocks with default = \"...\" whose name matches pass|secret|token|key"],
  "Password committed as a variable default in git (sensitive=true does not help).", requires=ENV)
# ---- c20 drift ----
p("drift-sg-ssh-opened", "c20", "roqy-lab-client-web", ["NEW-TF-DRIFT-SECURITY"], "P1",
  ["(client-shared, redacted) terraform show -json  vs  aws ec2 describe-security-groups --group-ids <id>"],
  "SG in code allows only 443 from the VPC; in the cloud someone added 22 from 0.0.0.0/0 by hand. Next apply silently removes it (or nobody ever looks).", requires=ENV)
p("drift-tag-changed", "c20", "roqy-lab-client-web", ["NEW-TF-DRIFT"], "P3",
  ["aws resourcegroupstaggingapi get-resources --resource-arn-list <arns from state>"],
  "Owner tag changed in console (platform-team -> someone-in-console) + extra hotfix tag: ownership/cost allocation drift.", requires=ENV)
# ---- c21 supply chain ----
p("iac-module-unpinned", "c21", "module.label", ["NEW-IAC-MODULE-PIN"], "P2",
  ["grep -nE 'source *= *\"git::' client-repo/infra/*.tf   # no ?ref=<tag|sha>"],
  "Module pulled from a git default branch: whoever pushes to it runs code in our next apply.", requires=ENV)
p("iac-provider-unconstrained", "c21", "hashicorp/aws", ["NEW-IAC-PROVIDER-PIN"], "P2",
  ["static: required_providers entries without version"],
  "No version constraint: a new runner pulls the latest major (aws v6 already broke this repo's AMI lookup).", requires=ENV)
p("iac-lockfile-ignored", "c21", ".terraform.lock.hcl", ["NEW-IAC-LOCKFILE"], "P2",
  ["git -C client-repo check-ignore -v .terraform.lock.hcl", "git -C client-repo ls-files '*.terraform.lock.hcl'"],
  "Lock file gitignored = no provider checksum pinning; CI and laptops can run different provider builds.", requires=ENV)
p("iac-ami-no-owners", "c21", "data.aws_ami.al2023", ["NEW-IAC-AMI-OWNERS"], "P1",
  ["static: data \"aws_ami\" with most_recent=true and no owners (allow_unsafe_filter=true silences the v6 guard)"],
  "Name-only most_recent AMI lookup: a community AMI named al2023-ami-* can win (whoAMI-style name confusion).", requires=ENV)
# ---- c22 CI/CD ----
p("cicd-pr-apply", "c22", "terraform.yml", ["NEW-CICD-PR-APPLY"], "P0",
  ["static: .github/workflows/* on: pull_request + 'terraform apply'"],
  "Every PR (incl. unreviewed branches) runs terraform apply against prod.", requires=ENV)
p("cicd-static-aws-keys", "c22", "terraform.yml", ["NEW-CICD-NO-OIDC"], "P1",
  ["static: secrets.AWS_ACCESS_KEY_ID / aws-access-key-id in workflows; no permissions: id-token: write"],
  "Long-lived IAM user keys in GitHub secrets instead of OIDC + role (the c1 leaked-key class).", requires=ENV)
p("cicd-prt-checkout-head", "c22", "pr-preview.yml", ["NEW-CICD-PRT-HEAD"], "P0",
  ["static: on: pull_request_target + actions/checkout with ref: github.event.pull_request.head.*"],
  "pwn request: attacker's fork code runs with the base repo's secrets and write token.", requires=ENV)
p("cicd-secrets-to-forks", "c22", "pr-preview.yml", ["NEW-CICD-FORK-SECRETS"], "P1",
  ["static: secrets.* referenced in a pull_request_target job"],
  "Secrets (AWS keys, DEPLOY_TOKEN) are handed to a job triggered by fork PRs.", requires=ENV)
p("cicd-write-all", "c22", "pr-preview.yml", ["NEW-CICD-PERMS"], "P2",
  ["static: permissions: write-all (or no permissions block)"], "GITHUB_TOKEN can push code, tags, releases.", requires=ENV)
p("cicd-unpinned-actions", "c22", "pr-preview.yml", ["NEW-CICD-ACTION-PIN"], "P2",
  ["static: uses: owner/repo@<not a 40-char sha>"], "Third-party actions on tags/branches (@main, @v4): tj-actions/changed-files 2025 class.", requires=ENV)
# ---- c23 Kubernetes ----
p("k8s-privileged-pod", "c23", "roqy-lab-priv-debug", ["NEW-K8S-PRIVILEGED"], "P1",
  [f"{RO_K} get pods -A -o json   # .spec.containers[].securityContext.privileged"], "privileged=true = root on the node.", requires=K8S)
p("k8s-hostpath-root", "c23", "roqy-lab-log-shipper", ["NEW-K8S-HOSTPATH"], "P1",
  [f"{RO_K} get pods -A -o json   # .spec.volumes[].hostPath"], "hostPath / mounted read-write = node filesystem (kubelet creds, other pods' tokens).", requires=K8S)
p("k8s-hostnetwork", "c23", "roqy-lab-net-probe", ["NEW-K8S-HOSTNETWORK"], "P2",
  [f"{RO_K} get pods -A -o json   # .spec.hostNetwork"], "hostNetwork=true: node IMDS/kubelet regardless of hop limit, bypasses NetworkPolicy.", requires=K8S)
p("k8s-imds-reachable", "c23", "roqy-lab-ng", ["NEW-K8S-IMDS"], "P1",
  ["aws ec2 describe-instances --filters Name=tag:eks:cluster-name,Values=<cluster> --query 'Reservations[].Instances[].MetadataOptions'",
   f"{RO_K} get networkpolicies -A -o json"],
  "Node HttpPutResponseHopLimit>=2 (or IMDSv1) and no egress policy blocking 169.254.169.254/32: any pod gets the node role.", requires=K8S)
p("k8s-irsa-broad-role", "c23", "billing-sa", ["NEW-K8S-IRSA-BROAD"], "P1",
  [f"{RO_K} get sa -A -o json   # eks.amazonaws.com/role-arn", "aws iam list-role-policies / get-role-policy --role-name <role>",
   "aws eks list-pod-identity-associations --cluster-name <cluster>"],
  "Workload SA mapped to an IAM role with service:* on * (here inert because of the lab guard boundary - still reported).", requires=K8S)
p("k8s-default-sa-automount", "c23", "roqy-lab-apps/default", ["NEW-K8S-SA-AUTOMOUNT"], "P3",
  [f"{RO_K} get sa default -n <ns> -o json", f"{RO_K} get pods -n <ns> -o json"],
  "default SA token automounted into pods that do not need the API.", requires=K8S)
p("k8s-no-networkpolicy", "c23", "roqy-lab-apps", ["NEW-K8S-NETPOL"], "P2",
  [f"{RO_K} get networkpolicies -n roqy-lab-apps"], "Workload namespace with zero NetworkPolicy (flat network, IMDS egress open).", requires=K8S)
p("k8s-sa-cluster-admin", "c23", "roqy-lab-ci-deployer-admin", ["NEW-K8S-RBAC-ADMIN"], "P0",
  [f"{RO_K} get clusterrolebindings -o json   # needs RBAC read (not in AmazonEKSViewPolicy)"],
  "ClusterRoleBinding cluster-admin -> ServiceAccount roqy-lab-apps/ci-deployer.", requires=K8S,
  notes="AmazonEKSViewPolicy (k8s 'view') cannot list RBAC objects; audit needs the roqy-audit-rbac-read group (see access/ + k8s/audit-rbac-reader.yaml).")
p("k8s-secret-env", "c23", "roqy-lab-billing", ["NEW-K8S-SECRET-ENV"], "P3",
  [f"{RO_K} get pods -A -o json   # env[].valueFrom.secretKeyRef (names only)"], "Secret injected as env var (leaks via /proc, crash dumps, debug `env`).", requires=K8S)
p("k8s-latest-image", "c23", "roqy-lab-priv-debug", ["NEW-K8S-IMAGE-LATEST"], "P3",
  [f"{RO_K} get pods -A -o json   # image tag latest/none, docker.io"], "busybox:latest from Docker Hub: unpinned, unscanned, mutable.", requires=K8S)
p("k8s-no-limits", "c23", "roqy-lab-priv-debug", ["NEW-K8S-NO-LIMITS"], "P3",
  [f"{RO_K} get pods -A -o json   # resources.limits"], "No CPU/memory limits: one pod can starve the node (noisy neighbour / cryptominer).", requires=K8S)
# ---- c24 Helm ----
p("helm-values-secrets", "c24", "roqy-lab-payments", ["NEW-HELM-VALUES-SECRETS"], "P1",
  [f"{RO_K} get deploy,cm -A -l app.kubernetes.io/managed-by=Helm -o json   # secret-like keys with literal values -> names only",
   "helm --kube-context roqy-lab-audit-ro list -A   # fails by design: release secrets not readable with view"],
  "Release values carry db.password / stripe.apiKey; Helm stores ALL values in sh.helm.release.v1.<rel>.v<N> (anyone with get secrets in the ns reads them; every revision kept).", requires=K8S,
  notes="View role cannot read Secrets -> proven by inference from rendered manifests; exact value keys need the client to run scripts/helm-values-keys.sh (prints key names only).")
p("helm-rendered-plaintext", "c24", "roqy-lab-payments-config", ["NEW-HELM-PLAINTEXT-RENDERED"], "P1",
  [f"{RO_K} get cm -n roqy-lab-apps -o json   # key names only"], "Chart renders STRIPE_API_KEY into a ConfigMap and DB_PASSWORD as literal env (readable with plain view).", requires=K8S)
p("helm-unverified-repo", "c24", "helmfile.yaml", ["NEW-HELM-REPO"], "P2",
  ["static: helmfile/Chart.yaml repositories with http:// or no verify, releases without version"],
  "Chart from an http, unverified repo with no version pin.", requires=ENV)
p("helm-image-latest", "c24", "roqy-lab-payments", ["NEW-K8S-IMAGE-LATEST"], "P3",
  [f"{RO_K} get deploy -n roqy-lab-apps -o json"], "Helm deployment image busybox:latest.", requires=K8S)
# ---- c25 chains ----
p("chain-pr-to-account", "c25", "terraform.yml", ["NEW-CHAIN-CICD-ACCOUNT"], "P0",
  ["correlate: NEW-CICD-PR-APPLY + NEW-CICD-NO-OIDC (+ NEW-CICD-PRT-HEAD)"],
  "Chain: anyone who can open a PR -> workflow runs terraform apply with long-lived AWS keys -> full control of the account.", kind="chain", requires=ENV)
p("chain-pod-imds-s3", "c25", "roqy-lab-eks-node", ["NEW-CHAIN-POD-IMDS-S3"], "P0",
  ["correlate: NEW-K8S-IMDS (+ PRIVILEGED/HOSTNETWORK) + node role S3 read on *"],
  "Chain: compromised pod -> node IMDS (hop 2, no egress policy) -> roqy-lab-eks-node credentials -> s3:GetObject on every bucket.", kind="chain", requires=K8S)
p("chain-state-db", "c25", "roqy-lab-legacy-db", ["NEW-CHAIN-STATE-DB"], "P1",
  ["correlate: NEW-TF-STATE-ACCESS + NEW-TF-STATE-SECRETS + NEW-RDS-EXPOSURE"],
  "Chain: any principal in the account reads state -> plaintext DB password -> publicly accessible RDS.", kind="chain", requires=ENV + ["rds"])


# ---- c26 container & dependency supply chain (static / free OSS) ----
p("docker-from-floating", "c26", "Dockerfile", ["NEW-DOCKER-FROM-PIN"], "P2",
  ["static: Dockerfile FROM ...:latest or untagged without @sha256 digest"],
  "Base image on a floating tag (latest / no tag) with no digest pin: builds are unreproducible and silently pick up new layers.", requires=ENV)
p("docker-pipe-shell", "c26", "Dockerfile", ["NEW-DOCKER-PIPE-SHELL"], "P1",
  ["static: RUN curl|bash / wget|sh inside Dockerfile"],
  "Pipe-to-shell inside the image build: remote script runs as root in the build context.", requires=ENV)
p("cicd-pipe-shell", "c26", "docker-build.yml", ["NEW-CICD-PIPE-SHELL"], "P1",
  ["static: .github/workflows/* step with curl|bash or wget|sh"],
  "CI step pipes a remote script into a shell (same class as Dockerfile pipe-to-shell).", requires=ENV)
p("docker-eol-base", "c26", "Dockerfile", ["NEW-DOCKER-EOL-BASE"], "P1",
  ["static: FROM python/node/ubuntu/... tag in a maintained local EOL list (no network)"],
  "Base image tag is past end-of-life (e.g. python:2.7, node:16): no security updates.", requires=ENV)
p("deps-unpinned-req", "c26", "requirements.txt", ["NEW-DEPS-UNPINNED"], "P2",
  ["static: requirements.txt lines without == / >= / ~= pins"],
  "Python deps without pins: tomorrow's pip install can differ from today's.", requires=ENV)
p("deps-no-lockfile", "c26", "package.json", ["NEW-DEPS-NO-LOCKFILE"], "P2",
  ["static: package.json present, no package-lock.json / yarn.lock / pnpm-lock.yaml"],
  "Node deps declared without a lockfile committed alongside.", requires=ENV)
p("docker-unpinned-install", "c26", "Dockerfile", ["NEW-DOCKER-UNPINNED-INSTALL"], "P2",
  ["static: RUN pip install <pkg> / npm install <pkg> without pin and not via -r requirements"],
  "Image build installs packages not pinned and not from a lock/requirements file.", requires=ENV)
p("deps-update-hygiene", "c26", "renovate.json", ["NEW-DEPS-UPDATE-HYGIENE"], "P3",
  ["static: renovate.json / dependabot.yml missing, or present without minimumReleaseAge / cooldown"],
  "No update bot cooldown: brand-new (and often malicious) releases can land the same day.", requires=ENV)
p("docker-add-remote", "c26", "Dockerfile", ["NEW-DOCKER-ADD-REMOTE"], "P2",
  ["static: ADD https://... without --checksum"],
  "Remote ADD without checksum: content can change under the same URL.", requires=ENV)
# ---- c27 AI agent supply chain ----
p("agent-prompt-inject", "c27", "SKILL.md", ["NEW-AGENT-PROMPT-INJECT"], "P0",
  ["static: .claude/skills/**/SKILL.md / .cursor/rules / AGENTS.md with ignore-previous / HTML-comment / exfil markers"],
  "Agent skill/rule instructs the model to ignore prior instructions or exfiltrate data (prompt injection).", requires=ENV)
p("agent-skill-script", "c27", "install.sh", ["NEW-AGENT-SKILL-SCRIPT"], "P0",
  ["static: skill-bundled scripts with curl|bash / eval / exfil URL"],
  "Skill ships an installer that pipe-to-shells or evals remote code with the agent's privileges.", requires=ENV)
p("agent-mcp-unpinned", "c27", "mcp.json", ["NEW-AGENT-MCP-PIN"], "P1",
  ["static: .cursor/mcp.json servers via npx -y pkg / uvx pkg@latest / git+ without commit SHA"],
  "MCP server package unpinned: a new publish runs under the agent's credentials next launch.", requires=ENV)
p("agent-mcp-secrets", "c27", "mcp.json", ["NEW-AGENT-MCP-SECRETS"], "P1",
  ["static: mcp.json env keys matching secret/token/api_key with non-empty values (names only)"],
  "MCP config hardcodes secret-like env values in the repo.", requires=ENV)
p("agent-mcp-broad-fs", "c27", "mcp.json", ["NEW-AGENT-MCP-FS"], "P2",
  ["static: filesystem MCP args include / or $HOME"],
  "Filesystem MCP granted the repo root of the machine (/ or home) instead of a narrow workspace path.", requires=ENV)


doc = {
  "schema_version": 1,
  "lab": "roqy vuln-lab",
  "severity_scale": "P0 critical / P1 high / P2 medium / P3 low-info",
  "conditions": {
    "allow_public": "terraform var allow_public=true", "foreign_account": "var foreign_account_id set to a 2nd account",
    "instance": "var instance_state != none (default running)", "weak_trail": "var create_weak_trail=true",
    "no_weak_trail": "var create_weak_trail=false (default)", "dns": "var dns_zone_type != none (default private)",
    "rds": "var enable_rds=true (default)", "eks": "var enable_eks=true (default)", "eks_old_version": "var eks_version set to a version in extended support", "second_region": "var enable_second_region=true (default)",
    "secrets_manager": "var enable_secrets_manager=true", "codebuild_webhook": "var codebuild_webhook_repo_url set",
    "kms_deletion": "var schedule_kms_deletion=true (default)",
    "envelope": "scripts/apply-envelope.sh deployed (envelope/, client-repo/, k8s/, helm/) - default ON",
    "absence_intact": "the sandbox owner has NOT enabled this account-level control manually (verify with the detect command first)",
  },
  "default_on_conditions": sorted(DEFAULT_ON),
  "matching": "A plant counts as detected when a finding has one of expected_check_ids AND mentions `resource` (or, for kind=absence with resource=account, only the check id). NEW-* ids do not exist in CHECKS-AWS.md yet: they are the gaps to add.",
  "plants": P,
}
here = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(here, "..", "EXPECTED-FINDINGS.yaml"), "w") as f:
    f.write("# GENERATED by scripts/gen_expected.py - edit that file, not this one.\n")
    yaml.safe_dump(doc, f, sort_keys=False, allow_unicode=True, width=140)
print(len(P), "plants;", sum(x["enabled_by_default"] for x in P), "enabled by default")
