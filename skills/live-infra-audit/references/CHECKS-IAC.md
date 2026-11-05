# Terraform / IaC checks (T1-T6, validated on a live canary)

| # | Check | Command | Finding if |
|---|---|---|---|
| T1 | State exists and is real | `terraform state list` in the client's IaC root | Empty state with live resources = IaC is decoration, everything is console-managed |
| T2 | Drift | `terraform plan -lock=false -input=false -no-color -detailed-exitcode` against the client backend. NEVER run `terraform import` (it writes the client real state) and NEVER run `init` or `get`. For drift on an empty state: copy the code to a throwaway dir with a local backend, use `import {}` blocks there, plan there. Never paste full plan output into the report: it can contain secrets | Plan shows changes nobody declared = manual console changes. Exit code 2 = drift |
| T3 | State security | Inspect backend config; local state file present? | State on disk unencrypted, no remote locking |
| T4 | Provider / module staleness | `terraform providers` + read required_providers and module sources; check registry for latest | Provider or module pinned to a version with known CVEs, deprecated, or >2 majors behind. Also: unpinned providers (no version constraint) |
| T5 | Plugin / toolchain EOL | `terraform version`; check tflint/checkov versions if installed | Terraform itself or audit tooling past EOL or with known CVEs |

| T6 | Expiry forecast | Registry check on pinned provider/module versions + deprecation notices | Pinned version deprecated or CVE-announced with fix available = upgrade window closing |

## Validated pitfalls

- An empty state + `plan -refresh-only` returns "No changes" — a false clean bill. Import the key resources first, then judge.
- google provider 6.x import ID for compute instances must be the full path `projects/<p>/zones/<z>/instances/<name>`; short `zone/name` fails with "non-existent remote object". Provider-level `zone` must be set or imports fail with "Cannot determine zone".
- Auth for local GCP runs: `export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)` — no service account needed for read-only audit. For AWS: the access key env vars work directly with the aws provider.
- Never run `terraform apply` in an audit. Plan and refresh-only are read-only. Import writes state to the configured backend (local file or remote S3/GCS), never touches real infrastructure, but on a remote backend it needs write access to the state bucket. If the client's credentials are read-only, import will fail — fall back to `plan -refresh-only` and mark drift needs_validation.

## Review order (how to review a client's Terraform)

1. Static first: tflint for logic, checkov/tfsec for policy (public bucket, open SG, missing encryption). Only if already installed — never install tools without asking.
2. Plan as the review artifact: read it like a diff. Every `+` on prod nobody discussed is a question; destroy on a resource with old state is the top red flag.
3. State: where it lives, who touches it, is there locking.
4. Drift: plan after importing the critical resources.
5. Hygiene: providers pinned to version, modules pinned to SHA/tag, no secrets in variables without sensitive=true.
