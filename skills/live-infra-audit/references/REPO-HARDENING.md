# Repo hardening fix list (the fixes for repo-layer findings, applied live)

When the repo-layer audit flags CI/CD gates or secret hygiene, these are the fixes in the order to apply. All are repo Settings clicks plus two small files; no code changes.

## Settings (in order)

1. Branch protection on main: require PR before merge, require status checks (all CI jobs), and CHECK "Do not allow bypassing the above settings". Without that checkbox, privileged actors and deploy keys push straight to main with a `remote: Bypassed rule violations` warning that still succeeds — protection looks active and blocks nothing. Verify with a real violating push: blocked = `GH006: Protected branch update failed`.
2. Solo maintainer: approving review count 0. GitHub forbids approving your own PR, so count 1 makes every PR unmergeable. The CI gate does the enforcing.
3. Code security: Secret scanning + Push protection + Dependabot alerts (free on public repos).
4. Advanced Security → Dependencies: enable Dependency graph AND click Save changes. dependency-review-action fails with "not supported on this repository" until it is on.
5. Account level: enforce 2FA. The same W4 check we run on clients applies to us.

## Files

- `.github/CODEOWNERS` with `* @owner` — every PR requests owner review.
- `SECURITY.md` — private reporting email, 72h response, safe harbor.
- `.gitignore` with `__pycache__/` before the first push, not after.

## CI (top-tier 2026 stack, one workflow)

Five jobs, all off-the-shelf except one: python syntax + smoke, gitleaks (secrets), zizmor (workflow-file security), dependency-review (vulnerable deps in PR), and the custom MD agent-safety scan (prompt-injection + destructive-command patterns + URL allowlist in markdown that agents will read — no template exists for it). Pin every action to its full commit SHA with the tag as a comment; tag references are mutable. Full recipe in the github skill's `references/ci-hardening.md`.

## Copilot code review

Free on public repos, adds a reviewer where there is no second human. It can only comment, never approve — it does not satisfy an approvals requirement.

## Deploy keys

A deploy key is not a user identity: if the key's public half is also registered as a user SSH key, GitHub resolves it to that user and the deploy key never engages (`Permission to repo denied to <user>`). Generate a dedicated keypair for the deploy key. SSH to GitHub on blocked hosts: `ssh://git@ssh.github.com:443/OWNER/REPO.git`.
