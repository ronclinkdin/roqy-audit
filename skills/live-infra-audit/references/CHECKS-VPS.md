# VPS / Docker checks (L1-L9, validated on the roqy VPS)

| # | Check | Command | Finding if |
|---|---|---|---|
| L1 | Public ports | `ss -tlnp` | Service bound to 0.0.0.0 that should be localhost (DB, admin UI, debug port). Verify reachability with `curl -sI http://<ip>:<port>` before calling it a finding |
| L2 | TLS | `openssl s_client -connect <host>:443 -servername <host> \| openssl x509 -noout -dates` | Cert expired or <14 days left |
| L3 | Restart policies | `docker inspect -f '{{.Name}} {{.HostConfig.RestartPolicy.Name}}' $(docker ps -q)` | `no` on a prod container |
| L4 | Image freshness | `docker images --format '{{.Repository}}:{{.Tag}}\t{{.CreatedSince}}'` | Prod image >6 months old or unpinned `:latest` on stateful services |
| L5 | Backups | `crontab -l` + `ls -lt <backup dir> \| head` | No backup cron, or output dirs empty/stale >7 days |
| L6 | Disk | `df -h` | Any filesystem >85% |
| L7 | Failed units | `systemctl list-units --state=failed` | Any failed service |
| L8 | Firewall | `ufw status` | Inactive while public services listen |
| L9 | SSH | `grep -E '^(PermitRootLogin\|PasswordAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*` | Password auth on or root password login |

Validated lessons: NPM admin UI on port 81 was publicly reachable while the repo looked clean; empty backup directories behind a healthy-looking cron were P0; sshd overrides live in /etc/ssh/sshd_config.d/50-cloud-init.conf.


## Expiry forecast (L10-L11)

| # | Check | Command | Finding if |
|---|---|---|---|
| L10 | TLS cert horizon | `openssl s_client -connect <host>:443 -servername <host> \| openssl x509 -noout -enddate` | Any cert <30 days out (Let's Encrypt 90-day certs: renewal already broken) |
| L11 | OS EOL | `cat /etc/os-release` | Base OS past or within 6 months of LTS EOL |
