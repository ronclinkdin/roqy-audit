# Client Onboarding — AWS read-only identity (screen by screen)

Send this to the client. Takes them 10 minutes. They keep admin, we get eyes only.

## Step 1: IAM user

1. AWS Console → IAM → Users → **Create user**.
2. Name: `roqy-audit`. Console access: **unchecked** (we never log in to the console).
3. Permissions: **Attach policies directly** → select `SecurityAudit`.
   - Alternative: `ReadOnlyAccess` (wider). `SecurityAudit` is enough for the audit.
4. Review → Create user.

## Step 2: Access key

1. Open the new user → **Security credentials** tab.
2. **Create access key** → use case: **Third-party service**.
3. Copy the Access Key ID and Secret. Send them to us over the agreed secure
   channel (never email, never chat plaintext). We store them in our key vault,
   encrypted, bound to the audit run.

## Step 3: What we do with it

1. `aws sts get-caller-identity` — shows the identity we will use. We send you
   this output and wait for your explicit yes before any live call.
2. Every command we run is `list` / `describe` / `get`. Nothing else.
3. After the audit you can delete the user, or keep it for recurring audits
   (recommended: rotate the key every 90 days).

## Step 4: Optional hardening (recommended)

- IAM → Policies → create `roqy-audit-deny` with `Deny` on `*:*` for
  `aws:PrincipalArn` = the audit user, scoped to write actions — belt and suspenders.
- Set a permissions boundary on the user so even a policy mistake cannot grant write.

## GCP variant

1. IAM & Admin → Service Accounts → Create `roqy-audit`.
2. Grant roles: `roles/viewer` + `roles/iam.securityReviewer`.
3. Keys → Add key → JSON → send securely.
4. We run `gcloud config list` + `gcloud auth activate-service-account` and show
   you the identity before the first live call.
