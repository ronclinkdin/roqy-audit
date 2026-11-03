# Portability (Claude Code, Cursor, and any Agent Skills host)

The skill follows the Agent Skills standard (agentskills.io). It contains no Hermes-specific instructions. Anything host-specific lives in this file, not in the skill body.

## Install paths

| Host | Path |
|---|---|
| Claude Code | `~/.claude/skills/live-infra-audit/` |
| Cursor | `~/.cursor/skills/live-infra-audit/` (also reads .claude/skills) |
| Hermes | profile skills directory |
| Any agentskills.io host | its skills directory |

## What is portable as-is

- SKILL.md router + references/ progressive disclosure: standard on Claude Code and Cursor.
- All check commands: plain shell (docker, ss, aws, gcloud, kubectl, terraform). No agent-specific tooling.
- Verdict rules, priorities, report format, scale guard: plain text rules any agent follows.
- Read-only safety rules: plain text.

## What is host-specific (do not copy into the skill body)

- The regression harness runs `hermes chat`. On Claude Code the equivalent is `claude -p "<prompt>"` with the skill installed; on Cursor, an agent session with the skill loaded. The validator (run_audit_harness.py validate) is host-independent python and works everywhere — only the `live` runner is Hermes-specific.
- Output directory convention `~/infra-readiness-audit/` is host-neutral and kept.
- Tool paths noted in reference files (/tmp/google-cloud-sdk, /tmp/terraform) are THIS server's paths. On a client machine the tools live wherever the client installed them; the skill says "use the platform CLI", the paths are examples.

## Claude Code specifics

- Claude Code reads references/ automatically through the skill's progressive disclosure; the router table in SKILL.md tells it which file to load.
- For the harness on Claude Code: `claude -p "$(cat scenario-prompt.txt)" --allowedTools "Bash" ` then run `python3 run_audit_harness.py validate <dir>`.
- Permission mode: the audit is read-only, so default permissions suffice; no --dangerously-skip-permissions needed for the audit itself.

## Rule for future edits

Every new check must be plain shell + plain text rules. If a check needs a host-specific capability, it goes in this file, never in the check tables.
