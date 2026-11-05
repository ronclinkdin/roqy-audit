# roqy-audit ENVELOPE coverage: vuln-lab run 2026-11-04 (Asia/Colombo)
Sandbox 856114194841, eu-central-1. Auditor = roqy-audit-sandbox (SecurityAudit + ViewOnly + explicit denies), k8s context roqy-lab-audit-ro.
36 new plants (c19-c25), EXPECTED-FINDINGS.yaml now 109 plants (95 default-on).

| run | k8s access | coverage | missed |
|---|---|---|---|
| 1 | AmazonEKSViewPolicy only | 35/36 = 97.2% | k8s-sa-cluster-admin (view cannot list RBAC) |
| 2 | + group roqy-audit-rbac-read (RBAC objects read, no Secrets) | **36/36 = 100%** | none |
Per category (run 2): c19 6/6, c20 2/2, c21 4/4, c22 6/6, c23 11/11, c24 4/4, c25 3/3. All severities match.
2 extra findings are true positives that were not planted (helm deployment without limits; its literal DB_PASSWORD env).
Runtime ~26 s, 0 errors except the by-design helm list denial.

Permission notes
- s3:GetObject on state is denied (explicit deny beats the bucket's broad Allow): NEW-TF-STATE-SECRETS = needs_validation (static inference).
- AmazonEKSViewPolicy: no Secrets (not even names), no RBAC objects, no nodes. RBAC added through a k8s group; Secrets deliberately NOT added.
  helm list fails (release storage = Secrets): releases found by Helm labels/annotations, values-secrets inferred from rendered env/ConfigMap; exact keys by client-side scripts/helm-values-keys.sh.
  Do NOT use AmazonEKSAdminViewPolicy: it reads Secret values.
- Drift: terraform plan as RO fails on ssm:GetParameter (see drift-plan-experiment.md); compare-based drift used instead.
- Still open from the core run: budgets:ViewBudget, ce:GetAnomalyMonitors (W7/W23).

Brief correction: the node's IMDS hop limit was 1 (IMDSv2 required), not 2. Set to 2 by envelope/ (out-of-band; re-apply after node replacement).
Proven admin-side (lab only): a non-hostNetwork pod reached IMDS and saw role roqy-lab-eks-node (role name only, no credentials fetched);
the Helm release secret decodes to values with db.password + stripe.apiKey (key names only printed).
Added cost: ~$0/month (<$0.10).
