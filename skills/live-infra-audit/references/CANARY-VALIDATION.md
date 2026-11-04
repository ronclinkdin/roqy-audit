# Canary validation

## The pattern

A canary is a deliberately dirty throwaway environment with known planted weaknesses. Run the full audit against it as if it were a client. Every planted issue MUST be detected; every compensating control MUST produce a rejected finding, not a confirmed one. A clean sandbox only proves the pipeline, not the value — say so explicitly in the report.

After a canary run, fold the exact working commands into the relevant reference file immediately — that is the moment the commands are freshest and proven. Delete exported canary keys from disk when done.

## Canaries run (2026-11-03)

| Canary | Planted | Detected | Rejected correctly |
|---|---|---|---|
| GCP project | open firewall, SA editor+key, VM cloud-platform scope, no budget, no snapshots, public bucket attempt | 5/5 | public bucket (org policy HTTP 412) |
| GKE cluster | privileged pod + hostPath /, LB on admin panel, cluster-admin to default SA, :latest no limits, zero netpol | 5/5 | kube-system noise (excluded by rule) |
| AWS account | public bucket with policy, open SG on 22 | 2/2 | object-ACL path (BucketOwnerEnforced) |
| AWS EKS default state | nothing planted — default-state findings | public endpoint, no netpol, no CloudTrail, no budgets | clean RBAC, no legacy SA tokens |
| roqy VPS (real, not canary) | none — real environment | 8 findings incl. 2 P0 the repo audit missed | TLS valid, restart policies ok |

## Provisioning lessons (when the canary needs IAM writes)

- After every create command, verify the resource exists with a get/list call. Filter pipes (head, tail) swallow AccessDenied errors and produce false ready states that fail minutes later at a deeper step.
- IAM write scopes are narrower than they look: PowerUserAccess denies iam:CreateRole and iam:PassRole. Have the account owner attach a scoped inline policy (create/attach/pass on eks* roles only) rather than admin.
- simulate-principal-policy can report allowed before a freshly attached inline policy propagates — re-probe with a real call before retrying the blocked operation.
- A cloud resource can stay ACTIVE while its referenced IAM role is missing; recreate the same-name role if a child-resource create reports the role not found.
- EKS on a fresh account needs eksClusterRole (AmazonEKSClusterPolicy) + eksNodeRole (AmazonEKSWorkerNodePolicy, AmazonEKS_CNI_Policy, AmazonEC2ContainerRegistryReadOnly) + instance profile before anything else.
- GKE on a fresh project: enable compute/storage/iam APIs first; org policies may block allUsers bindings (compensating control, not a failure).
- Cost discipline: canary clusters run minutes, not hours. GKE/EKS control plane ~$0.10/hr. Create, audit, delete in one session.

## AWS planting recipe (PowerUserAccess identity)

Plantable without IAM writes: S3 buckets + policies (public read/write, AuthenticatedUsers grant), EC2 security groups, EBS volume + snapshot shared to all, Secrets Manager secret without rotation, Lambda function with public Function URL, ECR repo with open pull policy, SNS topic with open publish policy, CloudWatch log group with no retention policy.
- Lambda needs a role trusted by lambda.amazonaws.com; PowerUserAccess blocks creating arbitrary roles, but a scoped eks* policy allows creating `eksLambdaRole` with the right trust — use that trick instead of asking for broader IAM.
- `describe-snapshots` does not return sharing state; verify snapshot exposure with `describe-snapshot-attribute --attribute createVolumePermission`.
- A log group with no retention policy IS the never-expire finding; `put-retention-policy` rejects 0, so plant by omission and read `retentionInDays: null`.
- IAM findings (dormant users, PassRole-on-*, NotAction policies) cannot be planted by PowerUserAccess — the account owner plants those, or the audit marks them rejected/not_applicable.

## Harness planted-coverage mapping

Map expected planted keywords by scenario prefix (aws-harness vs gcp-harness), never by a global substring like "canary": a global condition either skips the coverage check on differently-named run dirs or false-fails scenarios with unrelated plants. Each scenario's keyword list must name every planted artifact (bucket names, secret names, resource types) so a run that misses a plant goes RED.

## Credential recovery for canary reruns

Cloud credentials from earlier sessions live in the Hermes session database, not in env or ~/.aws. Recover them programmatically (search session DBs for the key prefix, parse the export or labeled lines), write to ~/.aws/credentials + config with 0600, and never print the values. A gcloud refresh token can expire between runs: the audit must then produce an all-not_applicable report (never fabricate), the harness correctly goes RED on missing planted coverage, and re-auth needs the account owner to complete the OAuth code flow via a pty background `gcloud auth login --no-launch-browser`.
