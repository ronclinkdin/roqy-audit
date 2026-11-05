# Client onboarding — AWS cross-account audit role (no static keys)

Send this to the client. They click once, we assume the role with an ExternalId
only they know. No IAM user, no access key, nothing to rotate or leak.
This is the same pattern we audit for (W3, W10): static keys are a finding.

## Step 1: One-click CloudFormation

1. Client opens the CloudFormation "Create stack" link we send (template:
   `cloudformation/audit-role.yaml` in this repo).
2. One parameter: the ExternalId (we generate a random string per client and
   send it over the agreed secure channel).
3. Client checks "I acknowledge that AWS CloudFormation might create IAM
   resources" and creates the stack.

What the stack creates:

- Role `roqy-audit-<client>` in the client's account.
- Trust policy: Principal = our audit account's role, Condition
  `sts:ExternalId` = the client's ExternalId. Nobody else can assume it, and a
  stolen ExternalId alone is useless without our role ARN.
- Attached policies: `SecurityAudit` + `ViewOnlyAccess`. Read-only by AWS's
  own definition, plus explicit Deny on every write action as belt and
  suspenders.

## Step 2: What we do with it

1. `aws sts assume-role --role-arn <client-role-arn> --external-id <id>` —
   temporary credentials, auto-expiring, never stored.
2. Every command we run is `list` / `get` / `describe`. The full command log
   is delivered to the client after the audit.
3. The ExternalId is single-client. Compromise of one client's ExternalId
   grants nothing on any other client.

## Step 3: Offboarding

Client deletes the CloudFormation stack. The role and its permissions vanish.
Nothing to rotate, nothing left in our vault.

## GCP variant

No JSON keys. The client grants `roles/viewer` + `roles/iam.securityReviewer`
to a principal from our Google Cloud identity via Workload Identity
Federation, or (simplest for small clients) we run the audit from a session
the client creates: `gcloud auth login` on a machine they control, or a
short-lived federated token. We never hold a downloadable key file.

## Why not an IAM user with a key?

Because that is finding W3 in our own audit: long-lived access keys are the
most leaked credential class in the public record (Truffle 2026: 9,300 live
keys in public repos). Asking the client to create one for us would make the
onboarding the first violation of the audit.
