---
name: live-infra-audit
description: "Live read-only infrastructure audit against what is actually running: Docker/VPS servers (containers, exposed ports, TLS, backups, restart policies) and cloud accounts via read-only identity. Use when asked to audit a live server, check what is running in production, verify backups/TLS/ports on a VPS, or extend a repo audit with real runtime evidence. Companion to infra-readiness-audit (repo layer) and security-audit (code layer)."
---

# Live Infra Audit

Audit what is actually running, not what the repo claims. Read-only always. Output: evidence-backed findings with P0/P1/P2, same verdicts as infra-readiness-audit (confirmed / needs_validation / rejected).

## Hard safety rules

1. Read-only commands only: `docker ps/inspect/images/stats`, `ss -tlnp`, `curl -I`, `openssl s_client`, `df`, `crontab -l`, `systemctl status`, cloud `list/get/describe` calls.
2. Never restart, stop, exec into, or reconfigure anything. Never send load or probes to third-party endpoints beyond a single HEAD request to the audited host.
3. Never print secret values. Redact to first 4 chars. Do not read secret file contents, only names/permissions.
4. Ask before touching a server that is not the one you were pointed at. Confirm target host with the user first.
5. Write output outside the repo: `~/infra-readiness-audit/<host>/<date>/live.md`.

## Phase 1: Inventory (Docker/VPS target)

Run and record:
- `hostname; uname -r; uptime` — host, kernel, reboot age.
- `docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'` — every container, image, restarts.
- `docker ps -a --filter status=exited --format '{{.Names}}\t{{.Image}}'` — dead weight.
- `ss -tlnp | grep -v 127.0.0.1` — everything listening on a public interface.
- `docker images --format '{{.Repository}}:{{.Tag}}\t{{.CreatedSince}}'` — image age.
- `df -h / /mnt* 2>/dev/null; free -m` — disk and memory headroom.
- `crontab -l` and `ls /etc/cron*` — scheduled jobs (backups, renewals).
- `systemctl list-units --state=failed` — failed services.

## Phase 2: Checks

| # | Check | Command | Finding if |
|---|---|---|---|
| L1 | Public ports | `ss -tlnp` | Service bound to 0.0.0.0 that should be 127.0.0.1 (DB, admin UI, unauthenticated API) |
| L2 | TLS | `curl -sI https://<host>` + `openssl s_client -connect <host>:443 -servername <host> 2>/dev/null \| openssl x509 -noout -dates` | Cert expired or <14 days left; http not redirected |
| L3 | Restart policy | `docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' $(docker ps -q)` | `no` on a prod container |
| L4 | Image freshness | `docker images` | Prod image >6 months old or `:latest` unpinned on stateful services |
| L5 | Backups exist | `crontab -l`, `ls -lt <backup dir> \| head` | No backup cron, or newest backup >7 days old |
| L6 | Disk headroom | `df -h` | Any filesystem >85% |
| L7 | Failed units | `systemctl list-units --state=failed` | Any failed service on the host |
| L8 | Kernel/host age | `uname -r; uptime` | Reboot pending >90 days or kernel far behind distro release |
| L9 | Firewall | `ufw status` or `iptables -L -n \| head -30` | No firewall rules with public services present |
| L10 | Auth surface | `ss -tlnp` for sshd; `grep -E '^(PermitRootLogin|PasswordAuthentication)' /etc/ssh/sshd_config` | Password auth on, root login without key-only |

Cloud target (only with user-approved read-only identity): run the relevant sections of infra-readiness-audit CHECKS.md live (public buckets, security groups 0.0.0.0/0, unencrypted RDS, no backups, IAM keys >90d).

## Phase 3: Verify

For each candidate: re-run the command, confirm the evidence is current, look for a compensating control (reverse proxy in front, firewall elsewhere, backup verified elsewhere). Assign confirmed / needs_validation / rejected. Only confirmed get priority.

## Priorities

- **P0:** public DB/admin port, expired TLS on the main domain, no backups of customer data, disk >95%.
- **P1:** no restart policy on prod container, backups stale >7d, disk >85%, password SSH auth, no firewall.
- **P2:** stale images, dead containers, pending reboot, unpinned :latest on stateless services.

## Report

Write `live.md`: inventory table, findings with exact command output as evidence (redacted), consequence, smallest fix, effort. Keep it under one page per 10 findings.
