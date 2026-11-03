# Terraform / IaC checks (T1-T3, validated on a live canary)

| # | Check | Command | Finding if |
|---|---|---|---|
| T1 | State exists and is real | `terraform state list` in the client's IaC root | Empty state with live resources = IaC is decoration, everything is console-managed |
| T2 | Drift | `terraform plan -input=false` after `terraform import` of key resources | Plan shows changes nobody declared = manual console changes |
| T3 | State security | Inspect backend config; local state file present? | State on disk unencrypted, no remote locking |

## Validated pitfalls

- An empty state + `plan -refresh-only` returns "No changes" — a false clean bill. Import the key resources first, then judge.
- google provider 6.x import ID for compute instances must be the full path `projects/<p>/zones/<z>/instances/<name>`; short `zone/name` fails with "non-existent remote object". Provider-level `zone` must be set or imports fail with "Cannot determine zone".
- Auth for local GCP runs: `export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)` — no service account needed for read-only audit. For AWS: the access key env vars work directly with the aws provider.
- Never run `terraform apply` in an audit. Plan and refresh-only are read-only; import writes only local state.

## Review order (how to review a client's Terraform)

1. Static first: tflint for logic, checkov/tfsec for policy (public bucket, open SG, missing encryption). Only if already installed — never install tools without asking.
2. Plan as the review artifact: read it like a diff. Every `+` on prod nobody discussed is a question; destroy on a resource with old state is the top red flag.
3. State: where it lives, who touches it, is there locking.
4. Drift: plan after importing the critical resources.
5. Hygiene: providers pinned to version, modules pinned to SHA/tag, no secrets in variables without sensitive=true.
