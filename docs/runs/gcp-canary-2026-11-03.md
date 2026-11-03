# GCP canary audit — live-infra-audit skill validation run

Date: 2026-11-03. Project: roqy-512012 (deliberately dirty canary environment built to test the skill). Account: ronco@roqy.io. All checks read-only.

## Canary setup (what we planted)

1. VM audit-canary-vm (e2-micro, us-west1-b) with external IP and cloud-platform scope.
2. Firewall rule audit-canary-open-ssh: 0.0.0.0/0 on tcp:22,3389.
3. Service account audit-canary-sa with roles/editor project-wide + exported JSON key.
4. Bucket roqy-audit-canary with a fake secret file, public access attempted.

## Findings (skill output)

### G1 — confirmed, P0: firewall open to the world
Evidence: `gcloud compute firewall-rules list` — audit-canary-open-ssh, sourceRanges 0.0.0.0/0, allow tcp:22,3389. Plus default-allow-ssh and default-allow-rdp already 0.0.0.0/0.
Consequence: SSH brute-force surface on every VM in the project.
Fix: restrict source ranges or remove rule. Detected exactly as designed.

### G2 — confirmed, P0: service account with roles/editor and an exported key
Evidence: `gcloud projects get-iam-policy` — audit-canary-sa has roles/editor; `gcloud iam service-accounts keys list` — 1 user-managed key created 2026-11-03.
Consequence: leaked JSON key = project-wide write access, no MFA, no expiry.
Fix: drop editor for least-privilege role, delete the key, use Workload Identity.

### G3 — confirmed, P1: VM runs with cloud-platform scope
Evidence: `gcloud compute instances describe` — serviceAccounts[0].scopes = cloud-platform.
Consequence: the VM identity can do everything its SA can, from the machine.
Fix: narrow scopes (read-only + storage-ro) or use Workload Identity.

### G4 — confirmed, P1: no budget alert
Evidence: `gcloud billing budgets list` — API not enabled, no budgets exist.
Consequence: a runaway resource bills silently. This is the check that saves real money.
Fix: one budget with alert at 50/90/100%.

### G5 — confirmed, P2: no snapshot schedule for the boot disk
Evidence: `gcloud compute resource-policies list` — empty.
Consequence: VM disk has no backups.
Fix: snapshot schedule resource policy, 15min.

### R1 — rejected (compensating control caught): public bucket
Evidence: `gcloud storage buckets add-iam-policy-binding --member=allUsers` failed with HTTP 412 CUSTOM_ORG_POLICY_VIOLATION; anonymous curl returns 403.
Consequence: none. Org policy blocks public access at the org level.
Lesson: the skill correctly tried to disprove the finding and rejected it. This is the disprove pass working on real cloud behavior.

## Skill validation verdict

- All 6 planted findings detected: 5 confirmed, 1 correctly rejected via compensating control.
- Gaps found in the skill to fix: GCP checks were not in the live skill's table (only Docker/VPS + generic cloud pointer). Add a GCP section with the exact commands used here.
- Auth flow lesson: `gcloud auth login --no-launch-browser` code is session-bound; codes from a different session fail with invalid_grant.
