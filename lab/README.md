# Lab

Sandbox for the AWS audit. The pytest suite does not call AWS and does not need credentials.

| Path | What |
|---|---|
| `vuln-lab/` | Terraform for the core lab, `access/` (read-only audit role and EKS access entry), `envelope/` plants, `client-repo/` (bad backend, CI, helmfile), Kubernetes and Helm manifests, `scripts/` (`score.py`, `redact-state.py`, `apply-envelope.sh`), `EXPECTED-FINDINGS.yaml` |
| `lab-run/` | v3 executors and the check catalog: `audit_v3.py`, `audit_envelope.py`, `checks-v3.yaml`, `gen_checks_v3.py`, plus the run notes |
| `harness-loop/` | Propose, probe, compose loop. The grader is hidden from the proposer. `guard.py` allowlists read-only verbs before any `aws`, `kubectl`, or `helm` call |

`vuln-lab/README.md` and `harness-loop/README.md` are in Hebrew.

`EXPECTED-FINDINGS.yaml` has 123 plants, 108 on by default. The latest static slice is c26 (Docker and dependencies) and c27 (agent skills and MCP): 14 plants, scored 14/14 on `client-repo` and 0 findings on `harness-loop/variants/clean-repo`. Those checks run with `audit_envelope.py --static-only` and do not call AWS.

## Audit role

`vuln-lab/access/` builds `roqy-audit-sandbox`:

- `SecurityAudit` + `ViewOnlyAccess`
- explicit denies on writes, secret values, and object data (`s3:GetObject`, `secretsmanager:GetSecretValue`, `ssm:GetParameter`, `kms:Decrypt`)
- a short allow on metadata reads those two policies omit: `budgets:ViewBudget`, Cost Explorer anomaly reads, `elasticbeanstalk:CheckDNSAvailability`, `ssm:GetDocument`, `savingsplans:DescribeSavingsPlans`
- EKS access entry with `AmazonEKSViewPolicy` (the `view` ClusterRole: no Secrets) plus the `roqy-audit-rbac-read` group so RBAC objects are visible. Do not switch this to `AmazonEKSAdminViewPolicy`; that policy can read Secret values, including Helm release secrets

## Run the tests

From the repo root:

```bash
python3 -m pip install pytest pyyaml
python3 -m pytest -q lab/harness-loop/tests
```

Paths in `harness-loop/config.yaml` are relative to the repo root. `probe.py` resolves them. Auditor files stay outside git, at the repo root: `.auditor-config`, `.auditor-bot-creds`, and `.kube/lab.kubeconfig` (override the kubeconfig with `AUDIT_KUBECONFIG`).

A live probe (`python3 probe.py --run runs/baseline-live` from `lab/harness-loop`) does call AWS with the read-only profile. `audit_v3.py` imports `awsrun`, which is the replay/live AWS CLI wrapper and is not part of this tree.

## Fixtures

Values that look like keys in `vuln-lab/terraform/main.tf` (an `AKIA` id, a `ghp_` token, and an `sk_live_` string, each marked FAKE in the name) are planted fixtures so detectors and the lab checks have something to see. They are not credentials.

Terraform state, `.terraform/`, kubeconfigs, `lab-run/raw/`, `lab-run/envelope/` (command dumps and redacted state), and `harness-loop/runs/*` except `ledger.jsonl` are gitignored.
