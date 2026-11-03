# AWS EKS canary audit — default-state validation run

Date: 2026-11-03. Cluster: audit-harness-eks (eu-central-1, 1x t3.small nodegroup). Nothing planted: this validates detection of DEFAULT-state findings, which is what a fresh client cluster looks like.

## Findings (default EKS state)

| Check | Verdict | Evidence |
|---|---|---|
| K1 public API endpoint | CONFIRMED P1 | endpointPublicAccess=True (EKS default), no CIDR restriction |
| K12 no NetworkPolicy | CONFIRMED P1 | zero netpol objects cluster-wide |
| K9 cluster-admin | PASS | only system bindings (cluster-admin to system:masters, eks:addon-cluster-admin) |
| K13 legacy SA secrets | PASS | default SA has no static token secret (modern EKS uses projected tokens) |
| A-CloudTrail | CONFIRMED P1 | describe-trails: zero trails. Changes to the cluster leave no org-visible trail |
| A-Budgets | CONFIRMED P1 | describe-budgets: none. EKS bills ~$73/mo with no alert |
| A-Config/GuardDuty | CONFIRMED P2 | no recorders, no detectors |

## Operational lessons (went into the skill)

1. Fresh AWS account needs eksClusterRole + eksNodeRole + instance profile before EKS. PowerUserAccess cannot create IAM roles; the account owner must (scoped policy provided).
2. iam:PassRole must be granted explicitly even under PowerUserAccess. simulate-principal-policy can report allowed before the inline policy propagates — re-probe with a real call.
3. A cluster can be ACTIVE while its referenced role was recreated; nodegroup creation re-validates the cluster role. Recreate the same-name role if CreateNodegroup reports it missing.
4. EKS default = public endpoint. That is the single most common real-world EKS exposure and it is the default, not a mistake.

## Cost

Cluster + node ran ~40 minutes total across attempts: roughly $0.15. All deleted after the run.
