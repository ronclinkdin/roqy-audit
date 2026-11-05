# Drift via `terraform plan` as the read-only role: experiment (2026-11-04 21:37 Asia/Colombo)
Setup: admin pulled the client state into a throwaway dir (/tmp, mode 700), backend overridden to local,
`terraform init` in the copy only, then as roqy-audit-sandbox (RO):
`terraform plan -lock=false -input=false -no-color -detailed-exitcode -refresh=true`
Result (sanitized):
- plan found the drift: `aws_security_group.web will be updated in-place`: ingress 22 would be removed, Owner someone-in-console -> platform-team, hotfix tag removed.
- then **Error: reading SSM Parameter (/roqy-lab-client/prod/legacy-db/password)**: refresh calls ssm:GetParameter WithDecryption, explicitly denied for the audit role. exit 1.
- local state copy unchanged (plan never writes state); copy shredded afterwards.
Decision: NOT used as the primary method. It needs (a) the full unredacted state, including the DB password, on the auditor box, and
(b) secret-read permissions for refresh. Both break the "we never saw a secret" promise.
Primary method = client-redacted state (scripts/redact-state.py) compared with describe calls + tagging API (audit_envelope.py, section 3).
`terraform plan` stays a client-side step (the client runs it, sends only the resource addresses + action summary).
