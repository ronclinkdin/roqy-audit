# VPS / Docker checks (L1-L16, validated on the roqy VPS)

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

Validated lessons: host-header routing is the blind spot of port scans — a public reverse proxy (NPM/ALB) routing by Host header can reach internal-only hosts; test `curl -sI -H 'Host: <internal-host>' https://<public-proxy>/` for each known internal vhost. NPM admin UI on port 81 was publicly reachable while the repo looked clean; empty backup directories behind a healthy-looking cron were P0; sshd overrides live in /etc/ssh/sshd_config.d/50-cloud-init.conf.


## Indirect exposure (L12-L16: what port scans cannot see)

| # | Check | Command | Finding if |
|---|---|---|---|
| L12 | Outbound tunnels | `ps aux \| grep -E 'cloudflared\|ngrok\|frp\|autossh\|ssh -R' \| grep -v grep` | Tunnel process running = the internet reaches internal services with zero inbound ports. The biggest blind spot of every port scanner |
| L13 | Docker bypasses ufw | compare `ufw status` with `docker ps` published ports and `iptables -L DOCKER -n` | Published docker ports are reachable even with ufw active: docker writes iptables directly |
| L14 | IPv6 exposure | `ss -tlnp \| grep ':::'` + `ip6tables -L -n` | Service on `::` with no ip6tables rules = publicly reachable over IPv6 while the v4 firewall looks tight |
| L15 | Debug endpoints | `curl -s -o /dev/null -w '%{http_code}' https://<domain>/actuator/env /debug/pprof/ /metrics /_debug` | 200 on any = keys, heap dumps, internal topology exposed on the public domain |
| L16 | Dangling CNAME takeover | enumerate CNAMEs (crt.sh + zone), resolve each, check for provider NXDOMAIN/NOSUCHSERVICE responses | CNAME to a deprovisioned S3/CloudFront/Heroku target = anyone can claim your subdomain |

## Expiry forecast (L10-L11)

| # | Check | Command | Finding if |
|---|---|---|---|
| L10 | TLS cert horizon | `openssl s_client -connect <host>:443 -servername <host> \| openssl x509 -noout -enddate` | Any cert <30 days out (Let's Encrypt 90-day certs: renewal already broken) |
| L11 | OS EOL | `cat /etc/os-release` | Base OS past or within 6 months of LTS EOL |
