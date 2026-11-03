# Client-favorite checks (X1-X6, add to every audit)

| # | Check | Command / question | Finding if |
|---|---|---|---|
| X1 | AI/LLM key sprawl | grep env files for key prefixes (names only); ask who pays and whether keys are per-service | Shared company key, no spend caps. One leaked key = unlimited bill. Leads the pitch — everyone has AI keys, nobody governs them |
| X2 | Bus factor / offboarding | Ask what breaks if the one person who knows the deploy leaves | Critical paths held by one person, no offboarding checklist |
| X3 | PII in logs | Sample app logs and third-party loggers for request bodies, emails, tokens | Customer data in logs with retention = a breach that already happened, just not discovered |
| X4 | Dependency supply chain | `npm audit --omit=dev`, lockfile age, Dependabot/Renovate | Lockfile untouched for months, prod on EOL runtime |
| X5 | Secrets rotation | `aws iam list-access-keys` / GCP key `validAfterTime` | Keys older than 90 days, no rotation policy |
| X6 | Domain/DNS blast radius | `dig NS <domain>`; ask about registrar 2FA and who has access | Shared or 2FA-less registrar account. A hijacked DNS beats every other finding |

X1 lands hardest with 2026 clients: everyone has AI keys, almost nobody governs them. Lead with it in the pitch.


## Architecture questions (X7-X9: what scanners cannot see)

| # | Check | Finding if |
|---|---|---|
| X7 | Restore test | Backups exist but no successful restore in 90 days, or nobody can name who ran one. A backup without a restore test is a hypothesis |
| X8 | Blast radius | Everything in one region/AZ, one DNS provider, one registrar, one cloud account |
| X9 | AI/LLM key sprawl | Shared OpenAI/Anthropic/Bedrock keys, no per-team spend caps, no rotation. One leaked key = unlimited bill |
