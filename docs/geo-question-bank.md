# GEO question bank: questions that lead to the skill

Format per question: the exact phrasing people search, a 40-60 word direct answer (quotable by AI engines), and the skill section it maps to. Every answer must stand alone: AI engines lift the answer block, not the page.

## Cluster: "is my cloud safe"

Q: How do I know if my S3 bucket is public?
A: Run `aws s3api get-bucket-policy-status --bucket NAME`. If IsPublic is true, anyone on the internet can read it. The stronger test is anonymous: `curl -o /dev/null -w '%{http_code}' https://NAME.s3.REGION.amazonaws.com/KEY` returns 200 for a truly public bucket. Policy says intent, the curl proves reality.
Maps to: CHECKS-AWS W1, W33.

Q: What is the most common AWS misconfiguration?
A: Public S3 buckets and over-broad IAM policies. The pattern behind most disclosed incidents: a resource policy with Principal "*", an IAM key committed to a repo, or a snapshot shared to another account. Each is one line of config with account-wide blast radius.
Maps to: CHECKS-AWS W1-W5, W24-W34.

Q: Is an unattached security group a security risk?
A: Not by itself. A security group only matters when attached to an ENI that has a public IP. Flagging unattached groups produces false alarms; the real check is: open ingress on 22/3389/admin ports AND a public IP on the attached interface.
Maps to: CHECKS-AWS W2.

Q: What is IMDSv1 and why is it dangerous?
A: IMDSv1 is the instance metadata service that answers without a token. If an app has an SSRF bug, an attacker can read instance role credentials with one request. IMDSv2 requires a token fetch first, which blocks it. Datadog found 93% of EC2 instances still allow v1.
Maps to: CHECKS-AWS W15.

## Cluster: "what do attackers actually do"

Q: How do attackers find leaked cloud keys?
A: They search public GitHub for AKIA prefixes, scan public S3 buckets by guessed names, and read Terraform state files, which store every secret in plaintext. One researcher found about 900 public tfstate files, 41 with live AWS credentials. No exploit needed, just enumeration.
Maps to: DEADLY-DETAILS T1, RECON-PUBLIC.

Q: What is a Terraform state file leak?
A: terraform.tfstate records every attribute of every managed resource, including database passwords, IAM secret keys and TLS private keys, in plaintext. The `sensitive = true` flag only hides values from terminal output, not from the file. In the SCARLETEEL incident one state file exposed a key to a second AWS account.
Maps to: DEADLY-DETAILS T1, T2.

Q: Can a Docker container escape to the host?
A: Yes, without any kernel exploit, if it has the Docker socket mounted or runs privileged. The socket is the daemon's API; a container with it can create a new privileged container that mounts the host root. Privileged containers can escape via cgroup release_agent. Both are common in CI runners and monitoring agents.
Maps to: DEADLY-DETAILS D1, D2.

Q: What is the kubelet read-only port 10255?
A: An unauthenticated HTTP endpoint that returns every pod and its environment variables. If it is open, anyone who can reach the node reads the whole workload inventory with no credentials at all. It is deprecated but still enabled on many clusters.
Maps to: CHECKS-K8S K17.

## Cluster: "CI/CD security"

Q: What is pull_request_target and why is it dangerous?
A: A GitHub Actions trigger that runs a workflow from the base repository, with its secrets, on code from a fork's pull request. If the workflow checks out the PR head, attacker-controlled code runs with production secrets. It is the most common Actions misconfiguration; zizmor flags it.
Maps to: CHECKS-CI C1 (planned), repo CI gates.

Q: Why pin GitHub Actions to a commit SHA?
A: A mutable tag like v4 can be repointed to malicious code by the action's maintainer, or hijacked if their account is compromised. Pinning to a full commit SHA freezes the code you audited. OWASP lists tag pinning as a supply-chain risk; SHA pinning is the fix.
Maps to: our repo CI (SHA-pinned), REPO-HARDENING.

Q: How do I scan my GitHub Actions workflows for vulnerabilities?
A: Run zizmor on the repository. It detects pull_request_target misuse, excessive permissions, template injection, unpinned actions and credential exposure. It runs locally, needs no credentials, and is what mature teams gate their CI with.
Maps to: ci-workflow-security.yml.

## Cluster: "costs and expiry"

Q: When does my Lambda runtime stop working?
A: AWS blocks new function creates on a runtime after its deprecation date and blocks updates later. Node.js 16 was blocked for new functions in 2025. Check `aws lambda list-functions` against the published runtime support schedule; plan the upgrade before the block date, not after.
Maps to: CHECKS-AWS W17-W20.

Q: Why did my AWS bill jump?
A: Common causes: a Reserved Instance or Savings Plan expired, EKS auto-upgraded a node group, log retention set to never expire, or crypto-mining in an exposed ECS task. The audit skill forecasts each expiry date with the expected amount, so the jump is a line item, not a surprise.
Maps to: CHECKS-AWS W21-W23, W35, W45.

## Cluster: "process and trust"

Q: What is a read-only infrastructure audit?
A: An audit that only runs list, get and describe commands against your cloud account, plus single status-code HTTP probes. It never changes, restarts or probes under load. Every finding carries evidence from the API response, and the client can veto any network probe.
Maps to: SKILL.md hard safety rules, curl discipline.

Q: How is an AI agent audit different from a scanner?
A: A scanner runs a fixed checklist. An agent reads the account's actual shape, follows the chain (open bucket leads to state file leads to second account), rejects findings it cannot confirm, and writes a report with verdicts: confirmed, needs_validation, rejected. The rejected list is what makes it trustworthy.
Maps to: VALIDATION-AND-REPORTING.

Q: Can an audit be done without giving full admin access?
A: Yes. Read-only IAM policies covering list/get/describe across the services in scope are enough for the full audit. The canary runs of this skill used a PowerUser-scoped identity with zero write operations. Secrets are never printed; findings reference shapes, not values.
Maps to: SKILL.md, CANARY-VALIDATION.

## GEO rules for every page built from this bank

1. The answer block is 40-60 words, one paragraph, no hedging, no "it depends" without a follow-up.
2. One command per answer, verbatim and runnable.
3. Name one real incident or number per answer when it exists (Datadog 93%, 900 state files, PREMINT 2022).
4. The page links to the skill section and to the live canary report as proof.
5. FAQPage schema with the same question text as the H2.
