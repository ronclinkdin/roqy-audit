# Live Infra Audit — vps-harness (ubuntu-8gb-nbg1-1, <vps-ip>)

Date: 2026-11-04. Read-only. Raw output: raw/recon.txt, raw/checks.txt, raw/verify*.txt.

## Inventory

- Host: ubuntu-8gb-nbg1-1, kernel 6.8.0-139, Ubuntu 24.04.3 LTS, up 46d, load 1.28.
- 20 containers running (roqy-app, NPM, cal.com, langfuse, city-demo, n8n, radicale, vikunja, umami, crw, openserp, keyserv, php2shell, smtp-bridge).
- Public listeners (ss): 22, 80, 443, 81, 3040, 631, 6006, 8899, 8889, 8012, 4317.
- Disk: / 92% (6.1G free), /mnt volume 72%. Mem 3.4G/7.7G used, swap 2.7G/4G.
- Cron: goaccess analytics, daily full backup 02:00, healthcheck, harness2 night loop.
- Failed units: disk-automation.service, disk-monitor.service.
- TLS roqy.io: valid to 2027-01-02 (>30 days). OS not near EOL. No outbound tunnels. Debug endpoints on roqy.io: 404/redirect to homepage.

## Findings

### F1 — Public admin and observability ports reachable (CONFIRMED, P0)
Evidence: `curl -sI http://<vps-ip>:<p>` → 81:200 (Nginx Proxy Manager admin UI), 6006:200 (arize-phoenix serve --host 0.0.0.0), 3040:200, 631:200 (cupsd). ufw inactive; docker-proxy binds 0.0.0.0 and [::].
Consequence: NPM admin UI = full proxy/credential control from the internet. Phoenix exposes traces (may contain prompts/PII).
Fix: bind NPM admin to 127.0.0.1 or restrict via NPM access list + Hetzner firewall; stop Phoenix or bind to 127.0.0.1; disable cups or bind localhost. One change window with F2.
Effort: 1-2h.

If it stays: the panels are login pages indexed by Shodan, and the exposure window started when the ports opened. Default or weak credentials turn reachability into takeover.

### F2 — ufw inactive, docker bypasses host firewall (CONFIRMED, P1)
Evidence: `ufw status` → "Status: inactive". `iptables -L DOCKER -n` shows ACCEPT 0.0.0.0/0 for published ports (3000, 443, 81, 80, 5678, 5232, 3456, 7000...). ip6tables INPUT policy ACCEPT, empty. IPv6 listeners on [::] for 80/81/443/3040/631.
Consequence: every published docker port is internet-reachable on v4 and v6 regardless of any future ufw rules.
Fix: apply full ufw ruleset + DOCKER-USER chain restrictions in one window; verify every public service immediately after (roqy.io, demo.roqy.io, cal, n8n).
Effort: 2-3h.

If it stays: every future published docker port is instantly public with no firewall decision. The protection the team believes exists does not.

### F3 — SSH root password login enabled (CONFIRMED, P0)
Evidence: `/etc/ssh/sshd_config:PermitRootLogin yes`; `/etc/ssh/sshd_config.d/50-cloud-init.conf:PasswordAuthentication yes`.
Consequence: brute-forceable root password auth on port 22 (0.0.0.0 and [::]).
Fix: PermitRootLogin prohibit-password, PasswordAuthentication no (both files), reload sshd, keep key session open while testing.
Effort: 15min.

If it stays: brute force runs against root around the clock; sshd logs fill with attempts and one weak password ends the host. This is the single most probed surface on the internet.

### F4 — Backups land in /tmp only, no offsite, Supabase skipped (CONFIRMED, P0)
Evidence: backup-cron.log daily: "rclone: 'b2:' remote not configured — skipping offsite sync", "SUPABASE_DB_URL not set. Skipping Supabase backup." Script writes tars to /tmp (3.1G there). /backups newest file 2026-10-12 (23d old), subdirs June 9.
Consequence: /tmp is wiped on reboot; disk failure loses roqy app DB, cal.com, langfuse, city-demo, vikunja data. No durable or offsite copy of production data.
Fix: configure rclone b2 remote, point backup output to /backups (on the 148G volume), set SUPABASE_DB_URL, verify by listing B2 output files.
Effort: 1h.

If it stays: one disk failure or one rm in /tmp erases every backup. The restore capability the team believes in does not exist off-host.

### F5 — Root filesystem 92% full (CONFIRMED, P1)
Evidence: `df -h` → /dev/sda1 75G, 66G used, 6.1G avail (92%). /root 32G, /tmp 3.1G.
Consequence: DB writes and docker builds can fail; logs truncate.
Fix: prune docker (docker system prune -a on volume is at 72%, safe), move /tmp backup tars after F4 fix, clear /root caches.
Effort: 30min.

If it stays: the disk fills within weeks, writes fail, and containers crash in cascades. The failure arrives during the next deploy, at the worst hour.

### F6 — Disk automation units failed (CONFIRMED, P2)
Evidence: `systemctl list-units --state=failed` → disk-automation.service, disk-monitor.service both failed.
Consequence: the automated disk cleanup is dead while disk is 92% (F5).
Fix: `systemctl status` both, fix or mask them; add disk alert instead.
Effort: 30min.

### F7 — Stale and unpinned images (CONFIRMED, P2)
Evidence: docker images: calcom v6.2.0 8mo, langfuse:2 12mo, n8n 1.99.1 16mo, NPM latest 5mo, openserp 3mo. Stateful services on :latest (radicale, umami, vikunja).
Consequence: known CVEs accumulate; :latest pulls can silently change behavior.
Fix: pin digests for stateful services; schedule monthly image update window.
Effort: 1h.

### F8 — php2shell-target restart policy "no" (CONFIRMED, P2)
Evidence: `docker inspect` → /php2shell-target no. All other containers unless-stopped/always.
Consequence: lab container, does not restart after reboot. Low impact.
Fix: set unless-stopped or accept as lab.
Effort: 5min.

### F9 — Memory pressure, heavy swap (CONFIRMED, P2)
Evidence: free -m: 3.4G used, swap 2.7G/4G used. Load avg 1.28 on 8G host.
Consequence: latency spikes on DB-backed services.
Fix: cap Phoenix (6006) and non-prod containers memory; consider stopping unused lab containers.
Effort: 30min.

### F10 — 0.0.0.0-bound python helper services (CONFIRMED, P2)
Evidence: ss: python :6006 (phoenix), python3 :8899 (http.server), :8889 (proxy_auth.py), :8012 (judge_auth_proxy), :4317. curl from public IP: 8899/8889/8012/4317 not reachable (000) — likely Hetzner cloud firewall filters them; 6006 reachable (F1).
Consequence: binding to 0.0.0.0 relies on an external firewall that is not verified for all ports.
Fix: bind helpers to 127.0.0.1; document Hetzner firewall rules.
Effort: 30min.

## Not run
not_applicable: L16 CNAME takeover — no DNS zone/API access from this host in read-only scope.

## Execution order (one change window)
1. F3 SSH config (test key session open).
2. F1+F2+F10 firewall: ufw ruleset + DOCKER-USER + bind fixes, verify all public services right after.
3. F4 backups: rclone b2 + /backups output + SUPABASE_DB_URL, verify offsite files exist.
4. F5+F6 disk: prune, fix/mask failed units.
5. F7/F8/F9 maintenance window.
