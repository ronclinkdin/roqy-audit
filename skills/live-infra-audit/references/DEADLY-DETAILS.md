# Small but lethal: mechanisms across DevOps tools

Each entry: the one line that kills, how it actually works (mechanism), and the check. Sources: real incidents and public research. Read-only checks only.

## Docker

### D1: /var/run/docker.sock mounted into a container
Mechanism: the socket is the Docker daemon API over a unix socket. A container with it mounted can call POST /containers/create with Privileged: true, mount the host root at /host, and read everything. No kernel exploit needed: the isolation boundary is bypassed by design, because the daemon runs as root on the host and trusts whoever talks to the socket. Common in CI runners, Portainer, Watchtower, monitoring agents.
Check: `docker inspect $(docker ps -q) --format '{{.Name}} {{.HostConfig.Binds}}'` — any Binds entry containing docker.sock is P0.

### D2: --privileged or CAP_SYS_ADMIN
Mechanism: privileged removes all capability filtering and device cgroup limits. Classic escape with cgroup v1: inside the container, mkdir a cgroup, set notify_on_release, write the host path into release_agent, trigger release — the host kernel executes the script as root. Works because privileged containers can mount cgroupfs read-write.
Check: `docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} caps={{.HostConfig.Capabilities}}'`.

### D3: Docker API on TCP 2375 without TLS
Mechanism: 2375 is the unauthenticated plaintext API. Anyone who can reach the port IS root on the host, same as D1 but over the network. Shodan shows thousands.
Check: `ss -tlnp | grep 2375` + `curl -sI http://<host>:2375/version` (status code only).

## Nginx / reverse proxies

### N1: alias off-by-slash traversal
Mechanism: `location /static { alias /data/static/; }` — location without trailing slash, alias with one. Request `/static../etc/passwd` resolves to `/data/static/../etc/passwd` = `/data/etc/passwd`... actually nginx strips the location prefix and appends the remainder to the alias: `/data/static/` + `../etc/passwd`. One character of config, arbitrary file read on the server, including configs with secrets. Found at scale by the off-by-slash Burp extension.
Check: read every `location` + `alias` pair in the config; flag any location without trailing slash whose alias has one. Gixy automates this.

### N2: autoindex on a directory with infrastructure files
Mechanism: directory listing exposes .env, .git/, tfstate, backups. The Darkmoon 2026 lab chain started with exactly this: one unauthenticated GET.
Check: `grep -rn 'autoindex on' /etc/nginx/`.

## Git

### G1: core.fsmonitor RCE via malicious .git
Mechanism: fsmonitor is a performance feature: git runs the configured command on every status/add/commit. IDEs (VS Code, Cursor, Theia) run `git status` automatically the moment a folder is opened. If .git/config contains `fsmonitor = <attacker command>`, opening the folder executes it. Not exploitable via plain clone, but chained with buried bare repos (a .git inside the repo) it is. This is a feature, not a bug: no patch exists.
Check: `git config --get core.fsmonitor` in every repo; global hardening `git config --global core.fsmonitor false`.

### G2: CVE-2025-48384: recursive clone RCE
Mechanism: git strips trailing CR when reading config but preserves it when writing. A .gitmodules with a submodule path ending in CR makes the submodule check out to a shifted path; combined with a symlink, the attacker's post-checkout hook lands in .git/hooks and runs on the next commit. Public PoCs exist. Fixed in 2.43.7+.
Check: `git --version` on dev machines and CI runners.

### G3: .git/ served by the webserver
Mechanism: the objects database is downloadable; tools like git-dumper reconstruct the full source history, including deleted secrets. git-dumper itself was shown RCE-able by a crafted repo (justinsteven 2022).
Check: `curl -s -o /dev/null -w '%{http_code}' https://<domain>/.git/HEAD` — 200 is P0.

## Terraform

### T1: terraform.tfstate is a plaintext credential store
Mechanism: state records every attribute the provider returned: DB passwords, aws_iam_access_key secrets, tls_private_key private keys. `sensitive = true` is display-only. SCARLETEEL (Sysdig 2023): attacker found a tfstate in an S3 bucket with an IAM key for a SECOND account — one file, multi-account breach. A researcher scanning guessed bucket names found ~900 public state files, 41 with live AWS credentials. Terraform 1.10/1.11 ephemeral values and write-only arguments fix it going forward; existing state does not.
Check: find every backend: `grep -rn 'backend' *.tf`; if local, check the file for secret-shaped strings (report shape, never values); if S3, check bucket policy and public access block.

### T2: state in git history
Mechanism: .gitignore added after the first commit does nothing. `git log --all --full-history -- '*.tfstate'` pulls it back, including from forks made after deletion.
Check: `git log --all --full-history -- '*.tfstate' '*.tfstate.backup' '*.env'` — any hit means rotate everything in it.

## Kubernetes

### K1: default service account token automounted
Mechanism: every pod gets a JWT for its namespace SA unless automountServiceAccountToken: false. Any RCE in any pod = API access with that SA's permissions. Combined with a broad ClusterRoleBinding, one vulnerable pod is the cluster.
Check: `kubectl get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.automountServiceAccountToken}{"\n"}{end}'` + `kubectl get sa default -o jsonpath='{.secrets}'`.

### K2: etcd without client auth
Mechanism: etcd holds ALL cluster secrets. If reachable without certs, the cluster is over: `etcdctl get / --prefix --keys-only` lists everything, including every SA token.
Check: from a node, `ss -tlnp | grep 2379` and check `--client-cert-auth` in the etcd flags.

## CI

### C1: pull_request_target with checkout of the PR head
Mechanism: the workflow runs in the base repo context WITH secrets, but checks out attacker-controlled code. One `git apply`/build step later, the secrets are gone. The single most common GitHub Actions misconfiguration.
Check: zizmor flags it; manual: any workflow with `pull_request_target` + `ref: ${{ github.event.pull_request.head... }}`.

### C2: cache poisoning
Mechanism: actions/cache keys are attacker-influenceable in fork PRs; a poisoned cache entry (e.g. a malicious dependency tarball) is restored into a later trusted build. The artifact looks clean, the dependency does not.
Check: does any workflow restore a cache across a trust boundary (fork PR to main build)?

## Linux host

### H1: cron PATH / sudoers wildcards
Mechanism: `PATH=` in crontab without absolute paths: a writable dir earlier in PATH replaces the binary. sudoers with `ALL` wildcards: `sudo tar` with a crafted filename becomes arbitrary flags.
Check: `crontab -l` for relative paths; `grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/` for `*` in commands.

### H2: setuid on unexpected binaries
Mechanism: setuid runs as the file owner regardless of caller. A stray setuid copy of bash or a custom binary = instant root.
Check: `find / -perm -4000 -type f 2>/dev/null` — compare against the known-good short list.

## Sources
- justinsteven/advisories: git buried bare repos + fsmonitor (2022)
- Datadog Security Labs: CVE-2025-48384, SCARLETEEL
- gixy.org: nginx alias traversal; bayotop/off-by-slash
- Truffle Security: tfstate secret scanning; ~900 public state files research
- dark-moon.org 2026 lab: tfstate + autoindex chain
- hackingthe.cloud: etcd, SA tokens, container escapes
