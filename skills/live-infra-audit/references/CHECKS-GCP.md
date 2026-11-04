# GCP checks (G1-G6 + audit logs A1-A4, validated on a live canary project)

## Network / IAM / cost

| # | Check | Command | Finding if |
|---|---|---|---|
| G1 | Open firewall | `gcloud compute firewall-rules list --format='table(name,sourceRanges.list(),allowed[].map().firewall_rule().list())'` | 0.0.0.0/0 allowing tcp:22/3389 or management ports (check default rules too) |
| G2 | Over-privileged SA + exported key | `gcloud projects get-iam-policy $P --format='value(bindings.role,bindings.members)'` + `gcloud iam service-accounts keys list --iam-account=<sa>` | SA with roles/editor or owner AND a user-managed key |
| G3 | VM scopes | `gcloud compute instances describe <vm> --zone=<z> --format='value(serviceAccounts[0].scopes)'` | cloud-platform scope on a running VM |
| G4 | Budget alert | `gcloud billing budgets list --billing-account=<id>` | API disabled or zero budgets |
| G5 | Disk backups | `gcloud compute resource-policies list` | No snapshot schedule |
| G6 | Public bucket object | `curl -s -o /dev/null -w '%{http_code}' https://storage.googleapis.com/<bucket>/<object>` | 200 on an object that should be private. Never test with a write call; org policies block allUsers bindings (HTTP 412) — that is a compensating control, mark rejected |

Set `CLOUDSDK_CORE_PROJECT` explicitly for compute commands — gcloud silently errors asking for a project otherwise.

## Audit logs and change visibility

| # | Check | Command | Finding if |
|---|---|---|---|
| A1 | Admin activity trail | `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Factivity" AND timestamp>=\"<recent>\"' --limit=5 --format='value(protoPayload.methodName,timestamp)'` | Empty = changes invisible |
| A2 | Attribution | Same query with `--format='value(protoPayload.authenticationInfo.principalEmail)'` | Entries with no principal = shared accounts hide who did what |
| A3 | Watching the logs | `gcloud logging sinks list` + `curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" 'https://monitoring.googleapis.com/v3/projects/<p>/alertPolicies'` | Only the default _Required sink and empty alertPolicies = logs exist, nobody watches |
| A4 | Data access logs | `gcloud logging read 'logName:"cloudaudit.googleapis.com%2Fdata_access"' --limit=1` | Empty = bucket/secret reads unlogged. Default OFF in GCP |

Logs being on by default is not visibility. Always check who reads them (A3) and whether data access is logged (A4).

## Expiry forecast (G7-G8)

| # | Check | Command | Finding if |
|---|---|---|---|
| G7 | TLS cert horizon | `gcloud compute ssl-certificates list --format='table(name,expireTime)'` | Any cert <30 days out |
| G8 | Commitment / spend guard | `gcloud compute commitments list` + billing budget check | Commitments ending <90 days unowned, or LLM API keys with no budget cap |

## One-line killers (G9-G10)

| # | Check | Command | Finding if |
|---|---|---|---|
| G9 | TokenCreator on wildcard | `gcloud projects get-iam-policy <p> --format=json` and grep for `iam.serviceAccountTokenCreator` with wildcard members | Member can impersonate every service account in the project |
| G10 | Public invoker | `gcloud run services list --format='table(metadata.name,metadata.labels)'` + IAM policy per service; same for Cloud Functions | `allUsers` on invoker = private function turned public with its service account attached |

## Cloud connection pipeline (verified)

1. Connect: `gcloud auth login --no-launch-browser` in a pty background terminal, feed the browser code with process submit. Verify with `gcloud auth list` — the login can save the token even when gcloud prints a confusing error afterward, so always re-check auth list before retrying.
2. An OAuth verification code is one-time and bound to the PKCE challenge of the exact login link that generated it. A code from a different session or an earlier link fails with invalid_grant; ask for a fresh code from the current link, never reuse.
3. First commands: `gcloud projects list`, `gcloud projects get-iam-policy`, `gcloud iam service-accounts list`, `gcloud storage ls`, `gcloud billing accounts list`. Disabled APIs are a finding-adjacent note, not a blocker.
4. A clean sandbox account proves the pipeline, not the value. State that explicitly; real findings need a dirty environment.
5. Billing/credits: `gcloud billing accounts list` (or the cloudbilling REST endpoint with `gcloud auth print-access-token`) is the ground truth for whether credits/billing exist; a user's memory of credits is not.
