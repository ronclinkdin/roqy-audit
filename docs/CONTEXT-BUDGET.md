# Context Budget — how the audit never times out and never drowns the agent

The audit runs on a small-context agent. These rules are what keep a full run
inside one session without a crash or a timeout. They are baked into both
skills; this doc explains why.

## Rule 1: Batch to files, never to the conversation

Every phase appends its raw output to a file in the output directory
(`inventory.md`, `raw/`), then the agent reads back only summaries. The
conversation never holds more than one phase's distilled result.

## Rule 2: One phase per tool call

Recon, checks, verify, report are separate calls. A timeout or gateway restart
loses at most one phase; the files on disk are the resume point. Never run the
whole audit in one giant command.

## Rule 3: Filter at the source

- `docker ps --format` instead of full `docker inspect` dumps.
- `grep -c` and counts instead of full file listings.
- `head`/`tail` bounds on any command that can return thousands of lines.
- Never cat a log file. Grep it for the specific pattern the check needs.

## Rule 4: No subagent fan-out on flaky providers

The audit is designed to run parent-only. If the platform supports subagents
and they work, Phase 3 verification can use one; if not, a deliberate second
pass in the same session. The audit never depends on delegation to finish.

## Rule 5: Bounded per-check output

Each check in CHECKS.md / the live checks table returns at most ~20 lines of
evidence. If a check needs more, it writes to a file and the report cites the
file path plus the key lines.

## Rule 6: Resume protocol

If a run dies mid-way:

1. `ls ~/infra-readiness-audit/<target>/<date>/` — see which phases exist.
2. Re-run only the missing phase. Never redo recon if inventory.md is complete.
3. findings.json is the source of truth; the report is generated from it last.

## Rule 7: Timeout hygiene

- Every shell command gets an explicit timeout (default 60s, 300s for docker
  builds/inspects on big hosts).
- Network probes (`curl`, `openssl s_client`) get `-m 5` / `ConnectTimeout=15`.
- A hung command is killed, noted as `needs_validation`, and the run continues.
  One hung check never blocks the report.
