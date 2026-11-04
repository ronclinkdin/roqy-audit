# AWS checks (W1-W23, one-line killers W24-W32, evidence-based W33-W45)

| # | Check | Command | Finding if |
|---|---|---|---|
| W1 | Public S3 buckets | `aws s3api list-buckets`, then per bucket `get-bucket-policy-status` (IsPublic true) + anonymous `curl -s -o /dev/null -w '%{http_code}' https://<bucket>.s3.<region>.amazonaws.com/<key>` | IsPublic true or anonymous 200 |
| W2 | Open security groups | `aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpProtocol==`tcp` && IpRanges[?CidrIp==`0.0.0.0/0`] || Ipv6Ranges[?CidrIp==`::/0`]]].[GroupId,GroupName]'`, then for each hit check attachment: `describe-network-interfaces --filters Name=group-id,Values=<sg>` and whether the attached ENI has a public IP (`describe-network-interfaces --query 'NetworkInterfaces[].Association.PublicIp'`) | tcp:22/3389/admin from 0.0.0.0/0 or ::/0 (IPv6 is the common miss) AND attached to an ENI with a public IP. An unattached or private-only SG is needs_validation, not confirmed |
| W3 | Long-lived IAM keys | `aws iam list-users` then `list-access-keys --user-name <u>` with CreateDate | Keys older than 90 days, Active keys for departed users |
| W4 | Root MFA | `aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'` | 0 = root without MFA (P0) |
| W5 | Account-level S3 block | `aws s3control get-public-access-block --account-id <id>` | NoSuchPublicAccessBlockConfiguration = no account guardrail (P2) |
| W6 | CloudTrail | `aws cloudtrail describe-trails --query 'trailList[].Name'` | Zero trails = no change history (P1) |
| W7 | Budgets | `aws budgets describe-budgets --account-id <id>` | None = cloud bills with no alert (P1) |
| W8 | Config / GuardDuty | `aws configservice describe-configuration-recorders` + `aws guardduty list-detectors` | Both empty = no guardrails (P2) |
| W9 | EKS public endpoint | `aws eks describe-cluster --name <c> --query 'cluster.resourcesVpcConfig.endpointPublicAccess'` | True without CIDR restriction. This is the EKS DEFAULT, not a misconfiguration — the most common real-world exposure |

## Persistence / blind-spot checks (W10-W16, where nobody looks)

| # | Check | Command | Finding if |
|---|---|---|---|
| W10 | Cross-account trust | `aws iam list-roles` + read each AssumeRolePolicyDocument | Trust to an unknown account ID or wildcard principal = classic attacker persistence (T1098.003) |
| W11 | Dormant IAM users | `aws iam list-users` + `get-user`/`get-access-key-last-used` | No console/API activity in 90 days with active keys = dormant door or leftover backdoor |
| W12 | Imported EC2 key pairs | `aws ec2 describe-key-pairs --query 'KeyPairs[].{n:KeyName,d:CreateTime}'` | Key pairs created outside known provisioning windows |
| W13 | Lambda code drift | `aws lambda list-functions --query 'Functions[].{f:FunctionName,m:LastModified}'` | LastModified outside deploy history = possible UpdateFunctionCode backdoor |
| W14 | VPC endpoint policies | `aws ec2 describe-vpc-endpoints --query 'VpcEndpoints[].{id:VpcEndpointId,p:PolicyDocument}'` | Default full-access policy = exfiltration channel that also bypasses GuardDuty |
| W15 | IMDSv2 | `aws ec2 describe-instances --query 'Reservations[].Instances[].{i:InstanceId,md:MetadataOptions.HttpTokens}'` | optional = IMDSv1 reachable = SSRF steals instance credentials (the Capital One vector) |
| W16 | SCP coverage | `aws organizations list-accounts` + `list-policies-for-target` | Org accounts with zero SCPs inherit nothing |

## Expiring / EOL resources (W17-W20)

| # | Check | Command | Finding if |
|---|---|---|---|
| W17 | Lambda runtime EOL | `aws lambda list-functions --query 'Functions[].{f:FunctionName,r:Runtime}'` | Runtime deprecated or in deprecation window (nodejs16.x, python3.8, etc.) — AWS blocks new invocations on the cutoff date |
| W18 | EKS version EOL | `aws eks describe-cluster --name <c> --query 'cluster.version'` | Version older than N-1 or past its ~14-month EOL — upgrade window closing, control plane auto-upgrades can break workloads |
| W19 | EC2 AMI age | `aws ec2 describe-images --owners self --query 'Images[].{id:ImageId,d:CreationDate}'` | AMIs >12 months old = unpatched base images; also check running instances' ImageId against this list |
| W20 | RDS engine EOL | `aws rds describe-db-engine-versions --engine <e> --query 'DBEngineVersions[].EngineVersion'` | Engine version past its community EOL (MySQL/Postgres majors) = no security patches |

## Expiry forecast (W21-W23: what breaks next, not what is broken now)

| # | Check | Command | Finding if |
|---|---|---|---|
| W21 | TLS cert horizon | `aws acm list-certificates` + `describe-certificate --query 'Certificate.NotAfter'` | Any cert <30 days out. Renewal automation already failed if it is this close |
| W22 | RI / Savings Plan end | `aws ce get-reservation-utilization` + `describe-savings-plans` | Plans ending <90 days with no renewal owner named = bill jump with no warning |
| W23 | AI/LLM spend guard | `aws ce get-anomaly-detectors` (cost anomaly detection exists?) + `aws bedrock list-custom-models` + `aws bedrock list-foundation-models --query 'modelSummaries[].modelId'` for usage surface | No cost anomaly detector while Bedrock or LLM API keys exist = one leaked key is an unlimited bill |

## One-line killers (W24-W32: the smallest config lines with the biggest damage)

| # | Check | Command | Finding if |
|---|---|---|---|
| W24 | PassRole on `*` | `aws iam list-attached-role-policies` + `get-policy-version` on every attached policy; grep for `iam:PassRole` with Resource `*` | Any principal can assume any role in the account = user-to-admin escalation primitive |
| W25 | NotAction policies | grep all policy documents for `NotAction` | "Everything except X" usually grants everything. Read what it actually allows |
| W26 | Cross-account KMS/Secrets policy | `aws kms list-keys` + `get-key-policy`; `aws secretsmanager list-secrets` + `get-resource-policy` | External account in a decrypt/get policy = all secrets behind it, no IAM touch needed |
| W27 | S3 notification to external account | `aws s3api get-bucket-notification-configuration --bucket <b>` | Lambda/queue/topic ARN owned by another account = silent exfiltration channel |
| W28 | SSM Session Manager logging | `aws ssm describe-document-permissions` + account SSM preferences | Session preferences without KMS encryption or CloudWatch/S3 logging = unattributed shell on every instance |
| W29 | CloudTrail single-region | `aws cloudtrail describe-trails --query 'trailList[].IsMultiRegionTrail'` | False = half the world's events unlogged |
| W30 | ECR public pull | `aws ecr describe-repositories` + `get-repository-policy` | `*` principal with pull = your images (and baked secrets) are world-readable |
| W31 | Confused deputy (no ExternalId) | read every cross-account trust policy for a missing `Condition: sts:ExternalId` | Partner role assumable by anyone inside the trusted account |
| W32 | Account-level EBS encryption | `aws ec2 get-ebs-encryption-by-default` | False = every future volume born unencrypted |

## Evidence-based checks (W33-W37: patterns from real breach data)

Sources: ramimac/aws-customer-security-incidents (2014-2024) + Datadog Security Labs + 2026 incidents: Sysdig TRT (AI-assisted 8-minute admin), Truffle Security (9,300 live exposed keys incl. 526 root), Arup/FulcrumSec, European Commission (Trivy supply chain), Beacon, Dow Jones (UpGuard).

| # | Check | Command | Finding if | Real precedent |
|---|---|---|---|---|
| W33 | S3 global write | read every bucket policy for `s3:PutObject` with Principal `*` | Anyone on the internet can plant files in your bucket. LA Times 2018, Twilio 2020, PREMINT 2022 all started here |
| W34 | Shared snapshots | `aws ec2 describe-snapshot-attribute --snapshot-id <id> --attribute createVolumePermission` per snapshot (describe-snapshots does NOT return sharing state) + `aws rds describe-db-snapshot-attributes` per RDS snapshot | Sharing contains group:all or another account = full disk copy with baked secrets. Imperva 2019 (RDS snapshot stolen), DNC 2016 (EC2 snapshots copied) |
| W35 | ECS exposure | `aws ecs list-clusters` + `describe-task-definition` per task: check for public ports, `aws ecs describe-services` | Task with exposed port = cryptojacking entry. Datadog 2024: "ECS is the new EC2 for crypto mining" |
| W36 | SES abuse guard | `aws sesv2 get-account` (production access, sending limits) + `aws sesv2 list-email-identities` | Production SES with no sending limit review = stolen key sends phishing as your domain. Kaspersky 2021, Rapid7 2024 |
| W37 | Secrets rotation | `aws secretsmanager list-secrets --query 'SecretList[].{n:Name,r:RotationEnabled}'` | RotationEnabled=false on secrets older than 90 days. FTX 2022: private keys in Secrets Manager, no rotation, no HSM |

| W38 | AuthenticatedUsers grants | read bucket policies/ACLs for grants to `AuthenticatedUsers` or `http://acs.amazonaws.com/groups/global/AuthenticatedUsers` | "Not public" but open to every AWS account holder. Dow Jones 2026: 2.2M customers via exactly this |
| W39 | Secrets in public build artifacts | scan public JS bundles/sourcemaps/build dirs for `AKIA`, `sk-`, PATs | Hardcoded token in a shipped artifact = repo access, then cloud access. Arup 2026 (PAT on forgotten subdomain -> 10k repos), Beacon 2026 (key in JS build -> full DB copy) |
| W40 | Root access keys exist | `aws iam get-account-summary --query 'SummaryMap.AccountAccessKeysPresent'` | 1 = a root key exists anywhere. Truffle 2026 found 526 live root keys in the wild. Delete all root keys, use roles |
| W41 | AI-named buckets | `aws s3 ls \| grep -iE 'openai\|llm\|gpt\|bedrock\|ai-\|-ai\|ml-\|model'` | Sysdig 2026: attackers grep for AI-tool naming conventions to find credential buckets fast |

| W42 | Host-header routing to internal hosts | `aws elbv2 describe-load-balancers` + `describe-listeners` + `describe-rules --listener-arns`: read every listener rule's HostHeader condition and target group; then `curl -sI -H 'Host: <internal-host>' https://<alb-dns>/` | A public ALB routes by Host header to a shared proxy that reaches internal-only hosts: internal panels, staging, admin UIs reachable from the internet through the front door. The SG check cannot see this — the ALB is legitimately public, the exposure lives in the routing rule |

| W43 | Lambda Function URLs | `aws lambda list-function-url-configs --query 'FunctionUrlConfigs[].{f:FunctionArn,a:AuthType}'` | AuthType NONE on a function that touches data = public endpoint created with one click, invisible in normal API audits |

| W44 | Open SNS/SQS policies | `aws sns list-topics` + `get-topic-attributes` per topic (read Policy); same for `sqs list-queues` + `get-queue-attributes` | Principal `*` with Publish/SendMessage = any account in the world can write to your topics and queues |
| W45 | Log retention | `aws logs describe-log-groups --query 'logGroups[].{n:logGroupName,r:retentionInDays}'` | retentionInDays null = never expire: unbounded cost plus PII retained forever. Two findings in one setting |

## Lessons (validated)

- New buckets are BucketOwnerEnforced, so object ACLs cannot make things public — check the bucket POLICY, not ACLs.
- Verify an identity is read-only with a write probe (create-bucket must return AccessDenied).
- PowerUserAccess can plant S3/EC2 findings but cannot write IAM; IAM findings are planted by the account owner and detected read-only via SecurityAudit.

## EKS setup on a fresh account (for canary runs)

1. Account owner creates eksClusterRole (AmazonEKSClusterPolicy) + eksNodeRole (AmazonEKSWorkerNodePolicy, AmazonEKS_CNI_Policy, AmazonEC2ContainerRegistryReadOnly) + instance profile.
2. Account owner grants the audit user iam:PassRole on those roles (scoped inline policy, not admin).
3. simulate-principal-policy can report allowed before a freshly attached inline policy propagates — re-probe with a real call before retrying.
4. A cluster can stay ACTIVE while its referenced IAM role is missing; recreate the same-name role if a child-resource create reports the role not found.
5. After every create command, verify the resource exists with a get/list call. Filter pipes (head, tail) swallow AccessDenied errors and produce false ready states.
