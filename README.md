# roqy-audit

Read-only infrastructure audit toolkit for startups without a DevOps engineer.
Built and battle-tested by [roqy.io](https://roqy.io) on our own stack first.

Three layers, one report:

| Layer | Tool | What it checks |
|---|---|---|
| Repo | `skills/infra-readiness-audit` | Secrets in git, CI/CD gates, Terraform state, review gaps |
| Live | `skills/live-infra-audit` | What is actually running: ports, TLS, backups, disk, restart policies |
| Change safety | [floci](https://github.com/floci-io/floci) (external) | Client IaC run against an emulated cloud before prod |

Methodology follows [Cloudflare's security-audit-skill](https://github.com/cloudflare/security-audit-skill):
recon before judgment, a pass that tries to disprove each finding, verdicts
`confirmed` / `needs_validation` / `rejected`, priority only for confirmed items.

## What we ran so far (real runs, real output)

1. **Repo audit of roqy itself** — 5 findings (2x P1 secrets/deploy gates, 2x P2, 1x monitoring). Report: `docs/runs/roqy-repo-2026-11-03.md`.
2. **Live audit of our own VPS** — 7 findings, including 2x P0 the repo audit could never see: NPM admin UI exposed on port 81, and Supabase backup directories empty despite the cron running. Report: `docs/runs/vps-live-2026-11-03.md`.

## Install

Copy the skill folders into your agent's skills directory:

```bash
cp -r skills/infra-readiness-audit ~/.claude/skills/
cp -r skills/live-infra-audit ~/.claude/skills/
```

## Run

```
run an infra readiness audit on this repo          # repo layer
audit the live server, read-only                   # live layer (confirms target first)
```

## Docs

- `docs/AGENT-RUNBOOK.md` — what the agent does, step by step, per client.
- `docs/CLIENT-ONBOARDING-AWS.md` — screen-by-screen: how the client creates the read-only identity.
- `docs/CONTEXT-BUDGET.md` — how the audit runs without timeouts and without blowing the agent's context window.
- `docs/runs/` — real audit reports from our own infrastructure.

## License

MIT
