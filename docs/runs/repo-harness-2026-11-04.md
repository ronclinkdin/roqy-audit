# Infra Readiness Report — roqy.io (/root/roqy)

Date: 2026-11-04. Commit: 140ece0 (working tree). Mode: static repo review only, no live cloud/cluster/GitHub API commands.

## Executive summary

Small single-operator Next.js stack on one VPS. Secrets discipline is unusually good for this size (env files never committed, SOPS+age for tracked secrets, containers localhost-bound behind Caddy). The gaps are operational: plaintext credentials in a committed compose file, an unattended auto-deploy to production as root, mutable third-party action refs with write permissions, no backups for the self-hosted analytics DB, and no alerting path to a human.

## Findings

### F1 — CONFIRMED — P1 — Plaintext credentials committed in docker-compose.yml
Evidence: `docker-compose.yml` lines for umami-db (`POSTGRES_PASSWORD: umam... (redacted)`) and umami (`APP_SECRET: roqy... (redacted)`), tracked in git (`git log -1 -- docker-compose.yml` → 22d4890).
Consequence: anyone with repo read access gets the analytics DB password and the Umami signing secret. Umami is localhost-bound, which limits remote exploitation, but the secret is now permanent git history and reusable if the DB is ever exposed (port change, firewall mistake, volume reuse).
Fix: move both values to `.env` (already git-ignored) and reference as `${UMAMI_DB_PASSWORD}` / `${UMAMI_APP_SECRET}`; rotate both values; optionally rewrite history with git-filter-repo. Hours. Good first task.

If it stays: the exposure compounds with every deploy until someone else finds it. Hours to fix today versus an incident later.

### F2 — CONFIRMED — P1 — Production auto-deploys on every push to main, as root, with no approval gate
Evidence: `.github/workflows/deploy.yml` — `on: push: branches: [main]`, SSH step `username: root`, script `git pull && docker compose up -d --build`. No environment protection, no manual approval, no CODEOWNERS in repo.
Consequence: a typo, a bad merge, or a compromised maintainer token reaches production within minutes with no human checkpoint. Root SSH key in GitHub secrets is a single credential that owns the whole VPS.
Fix: add a GitHub `production` environment with required reviewer (1 approval), and create a non-root deploy user with only docker-compose rights on the repo dir. Hours to a day. Good first task.

If it stays: the exposure compounds with every deploy until someone else finds it. Hours to fix today versus an incident later.

### F3 — CONFIRMED — P1 — Third-party action pinned to mutable ref with write permissions
Evidence: `.github/workflows/pr-agent.yml` uses `the-pr-agent/pr-agent@main` with `permissions: contents: write, pull-requests: write, issues: write`.
Consequence: if the upstream `main` branch is compromised, the next PR event runs attacker code with write access to the repo. `@main` is a moving target; this is the classic third-action supply-chain hole.
Fix: pin to a full commit SHA of a known release (or a fork you control), and drop `contents: write` if the agent only comments. Under an hour.

If it stays: the exposure compounds with every deploy until someone else finds it. Hours to fix today versus an incident later.

### F4 — CONFIRMED — P1 — No backups for the self-hosted Umami Postgres volume, never restore-tested
Evidence: `docker-compose.yml` defines named volume `umami-db-data` with no backup job anywhere in the repo (`grep -rniE 'backup' docker-compose.yml scripts` → no backup script for it; only content-pipeline text matches).
Consequence: volume corruption or a bad `docker volume rm` silently destroys all analytics history. Traffic data is the core pSEO decision input for this business.
Fix: nightly `pg_dump` to a second volume or off-box target (e.g. restic to object storage), plus one documented restore test. Half a day. Good first task.

If it stays: the exposure compounds with every deploy until someone else finds it. Hours to fix today versus an incident later.

### F5 — CONFIRMED — P1 — No alerting path to a human
Evidence: `scripts/healthcheck.sh` auto-restarts the app container and appends to `/var/log/roqy-healthcheck.log`; nothing in the repo sends a message on restart, on repeated failure, or on Sentry error spikes. Sentry DSNs are configured but no alert routing (PagerDuty/email/Telegram) is referenced.
Consequence: the site can be down or erroring for hours and nobody is woken up — the healthcheck masks failures by restarting, and the log file is only read if someone looks. For a lead-gen site, silent downtime is lost revenue with no signal.
Fix: add a Telegram/email notification at the end of healthcheck.sh on restart-or-failure, and enable Sentry alert rules to the same channel. Hours.

If it stays: the exposure compounds with every deploy until someone else finds it. Hours to fix today versus an incident later.

### F6 — CONFIRMED — P2 — GitHub Actions not SHA-pinned; no CODEOWNERS; no tests in CI
Evidence: `deploy.yml` uses `actions/checkout@v4`, `actions/setup-node@v4`, `appleboy/ssh-action@v1.2.0` (tags, not SHAs); no `.github/CODEOWNERS`; `package.json` has no test script — CI is lint+build only.
Consequence: tag refs are mutable (moderate risk for first-party actions); no ownership metadata; regressions ship because nothing but a successful build gates a deploy.
Fix: pin all actions to SHAs; add CODEOWNERS (`* @ronclinkdin`); add a minimal smoke test (build output + one API route check) to deploy.yml. Half a day.

### F7 — CONFIRMED — P2 — node_modules committed to git inside packages/mcp-server
Evidence: `git ls-files | grep -c node_modules` → 3687 tracked files under `packages/mcp-server/node_modules/`.
Consequence: repo bloat, noisy diffs, and vendored dependency code that can drift from package-lock and hide tampering.
Fix: add `packages/mcp-server/node_modules` to `.gitignore`, `git rm -r --cached`, rebuild via Dockerfile. Under an hour.

### F8 — NEEDS_VALIDATION
Evidence: static review cannot see GitHub repo settings; no branch-protection config exists in-repo (`.github/` has only the two workflows).
Consequence: if main is unprotected, force-pushes and direct pushes can bypass the (already thin) deploy gate entirely.
Validation needed: repo owner checks Settings → Branches → main requires PR + no force push. 5 minutes, owner only.

### F9 — NEEDS_VALIDATION
Evidence: app uses `SUPABASE_SERVICE_ROLE_KEY` server-side (`src/lib/supabase.ts` line 7) and anon keys client-side; repo contains no RLS policy files or backup configuration.
Consequence: if RLS is not enabled on tables reachable with the anon key, client-side data is exposed; if the Supabase plan has no PITR/backups, lead data has no recovery path.
Validation needed: owner checks Supabase dashboard — RLS enabled per table, auth users, and backup/PITR settings for the current plan.

### F10 — NEEDS_VALIDATION
Evidence: remote is `git@github.com-roqy:ronclinkdin/roqy.io.git`; static review cannot determine public/private.
Consequence: if public, F1's committed credentials are world-readable and F1 should be treated as P0 (rotate immediately).
Validation needed: owner confirms repo visibility; if public, rotate Umami credentials today.

## Rejected candidates (kept so nobody re-raises)

### R1 — REJECTED — Rate limiter trusts spoofable X-Forwarded-For
Evidence: `src/lib/rate-limiter.ts:143` `clientIp()` reads `x-forwarded-for` (last hop). Disproved as exploitable: the app container binds to `127.0.0.1:3000` (docker-compose.yml), so external clients cannot reach the app except through Caddy, which appends the real client IP as the last XFF entry; the code explicitly documents not trusting `x-real-ip`/XFF[0] (line 140). Direct connections from the same host would be a local attacker who already owns the box.

### R2 — REJECTED — Secrets committed to git (.env / keys)
Evidence: `git rev-list --all --count -- .env` → 0; `.env*` in `.gitignore`; tracked secret files (`secrets.enc.yaml`, `gsc-key.enc.json`) are SOPS/AES256-GCM encrypted with an age key whose private half is not in the repo. No `sk_live`/`sk_test`/`whsec` literals anywhere in src/scripts/packages.

## Not covered (and why)

- Live cloud IAM, Terraform drift, Kubernetes, cost alerts: not_applicable — no IaC or usage-based cloud in this repo; static-only audit per instruction.
- VPS-level state (firewall, SSH config, disk, actual cron entries, Caddy runtime): outside repo scope; not inspected.
- GitHub org/repo settings (branch protection, secret rotation dates, repo visibility): items F8/F10.
- Dependency vulnerability scan: gitleaks/trivy/checkov not installed; not installed per skill rule 7 (would ask before installing).

## Fix order

1. F10 check (5 min) — determines F1 urgency.
2. F1 rotate + move to env (hours).
3. F3 pin pr-agent SHA, drop contents:write (under an hour).
4. F5 alerting channel (hours).
5. F2 deploy environment gate + non-root deploy user (day).
6. F4 Umami backup + restore test (half day).
7. F6, F7 hygiene (day).
