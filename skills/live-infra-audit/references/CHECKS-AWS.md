# AWS checks (W1-W16, validated on a live canary account)

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
