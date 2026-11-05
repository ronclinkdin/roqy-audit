"""Static repo checks shared by the lab envelope runner and `roqy-audit scan`.

Detection logic is the lab envelope's repo pass (IaC, CI/CD, Helm, Docker/deps, agent skills/MCP).
`find` is the caller's sink so the lab can still apply its overlay. `param(name, default)` reads
optional knobs; the CLI uses the defaults.
"""
import glob, json, os, re, shutil, subprocess, sys

def _default_param(name, default):
    return default

def scan_static(repo, find, sec_key, param=None):
    """Run the static checks against `repo`. Returns the parsed Terraform backend dict or None."""
    if param is None:
        param = _default_param
    repo = os.path.abspath(repo)
    rel = lambda p: os.path.relpath(p, repo)

    tf_files = sorted(glob.glob(f"{repo}/**/*.tf", recursive=True))
    tf = {f: open(f).read() for f in tf_files}
    def blocks(src, head_re):
        """yield (header_match, body) for top-level HCL blocks matching head_re (brace counting)."""
        for m in re.finditer(head_re, src, re.M):
            i = src.index("{", m.start()); d = 0
            for j in range(i, len(src)):
                d += {"{": 1, "}": -1}.get(src[j], 0)
                if d == 0: yield m, src[i + 1:j]; break
    backend = None
    for f, s in tf.items():
        for m, body in blocks(s, r'backend\s+"(\w+)"\s*\{'):
            kv = dict(re.findall(r'^\s*(\w+)\s*=\s*"?([^"\n#]+)"?', body, re.M))
            backend = dict(type=m.group(1), file=f, **{k: v.strip() for k, v in kv.items()})
    if backend and backend["type"] == "s3":
        bf = rel(backend["file"])
        if "dynamodb_table" not in backend and backend.get("use_lockfile") != "true":
            find("NEW-TF-STATE-LOCK", bf, f"{bf}: S3 backend has no state locking (no use_lockfile, no dynamodb_table)", "P2", evidence=bf, layer="iac")
        if backend.get("encrypt") in (None, "false"):
            pass  # reported together with bucket encryption below
    for f, s in tf.items():
        for m, body in blocks(s, r'^variable\s+"([^"]+)"\s*\{'):
            dm = re.search(r'^\s*default\s*=\s*"([^"]+)"', body, re.M)
            if dm and sec_key.search(m.group(1)):
                find("NEW-TF-HARDCODED-SECRET", f"var.{m.group(1)}", f"{rel(f)}: variable {m.group(1)} has a hardcoded default (value not shown, {len(dm.group(1))} chars)", "P1", evidence=rel(f), layer="iac")
        for m, body in blocks(s, r'^module\s+"([^"]+)"\s*\{'):
            sm = re.search(r'source\s*=\s*"([^"]+)"', body)
            if not sm: continue
            src = sm.group(1)
            remote_git = src.startswith(("git::", "github.com/", "git@", "bitbucket.org/"))
            registry = re.match(r"^[\w-]+/[\w-]+/[\w-]+$", src)
            if remote_git and not re.search(r"[?&]ref=([0-9a-f]{40}|v?\d+\.\d+)", src):
                find("NEW-IAC-MODULE-PIN", f"module.{m.group(1)}", f"{rel(f)}: module.{m.group(1)} from {src} without ?ref= tag/sha", "P2", evidence=rel(f), layer="iac")
            if registry and not re.search(r"^\s*version\s*=", body, re.M):
                find("NEW-IAC-MODULE-PIN", f"module.{m.group(1)}", f"{rel(f)}: registry module {src} without version", "P2", evidence=rel(f), layer="iac")
        for m, body in blocks(s, r'^\s*required_providers\s*\{'):
            for pm, pb in blocks(body, r'^\s*([\w-]+)\s*=\s*\{'):
                src = (re.search(r'source\s*=\s*"([^"]+)"', pb) or re.search("()", "")).group(1) or pm.group(1)
                if not re.search(r'version\s*=', pb):
                    find("NEW-IAC-PROVIDER-PIN", src, f"{rel(f)}: provider {src} has no version constraint", "P2", evidence=rel(f), layer="iac")
        for m, body in blocks(s, r'^data\s+"aws_ami"\s+"([^"]+)"\s*\{'):
            if not re.search(r'^\s*owners\s*=', body, re.M):
                ex = " + allow_unsafe_filter=true (provider guard silenced)" if "allow_unsafe_filter" in body else ""
                find("NEW-IAC-AMI-OWNERS", f"data.aws_ami.{m.group(1)}", f"{rel(f)}: data.aws_ami.{m.group(1)} picks most_recent by name with no owners{ex}", "P1", evidence=rel(f), layer="iac")
        # secrets that WILL be in state (plaintext) even if marked sensitive
        for m, body in blocks(s, r'^resource\s+"(aws_ssm_parameter|aws_db_instance|aws_rds_cluster|random_password|aws_secretsmanager_secret_version|aws_iam_access_key|tls_private_key|aws_iam_user_login_profile)"\s+"([^"]+)"\s*\{'):
            typ, name = m.groups()
            attr = {"aws_ssm_parameter": "value", "aws_db_instance": "password", "aws_rds_cluster": "master_password", "random_password": "result",
                    "aws_secretsmanager_secret_version": "secret_string", "aws_iam_access_key": "secret", "tls_private_key": "private_key_pem", "aws_iam_user_login_profile": "password"}[typ]
            if typ == "aws_ssm_parameter" and not sec_key.search(body): continue
            if typ == "aws_db_instance" and "manage_master_user_password" in body: continue
            find("NEW-TF-STATE-SECRETS", f"{typ}.{name}", f"{rel(f)}: {typ}.{name}.{attr} is stored in PLAINTEXT in the remote state (state content not read: needs client-shared redacted state or `terraform show -json` key list)",
                 "P1", status="needs_validation", evidence=rel(f), layer="iac")

    git = lambda *a: subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)
    if tf_files:
        if git("ls-files", "--error-unmatch", "infra/.terraform.lock.hcl").returncode != 0 and not git("ls-files", "*.terraform.lock.hcl").stdout.strip():
            ign = git("check-ignore", "-v", "infra/.terraform.lock.hcl").stdout.strip()
            find("NEW-IAC-LOCKFILE", ".terraform.lock.hcl", f".terraform.lock.hcl not committed{' (gitignored: ' + ign.split(chr(9))[0] + ')' if ign else ''}: no provider checksum pinning", "P2", evidence=".gitignore", layer="iac")

    # ---- GitHub Actions ----
    try:
        import yaml
    except ImportError:
        sys.exit("pip install pyyaml")
    WF = {}
    for f in sorted(glob.glob(f"{repo}/.github/workflows/*.y*ml")):
        raw = open(f).read(); d = yaml.safe_load(raw); WF[os.path.basename(f)] = (d, raw)
    for name, (d, raw) in WF.items():
        on = d.get(True, d.get("on")) or {}
        on = {on: None} if isinstance(on, str) else ({k: None for k in on} if isinstance(on, list) else on)
        prt, pr = "pull_request_target" in on, "pull_request" in on
        perms = d.get("permissions")
        if perms == "write-all" or (isinstance(perms, dict) and any(v == "write" for v in perms.values()) and len(perms) > 4):
            find("NEW-CICD-PERMS", name, f"{name}: permissions: write-all (GITHUB_TOKEN can push/tag/release)", "P2", evidence=name, layer="cicd")
        elif perms is None and not all(isinstance(j, dict) and "permissions" in j for j in (d.get("jobs") or {}).values()):
            find("NEW-CICD-PERMS", name, f"{name}: no permissions block (inherits repo default token scope)", "P3", evidence=name, layer="cicd")
        uses_keys = bool(re.search(r"secrets\.AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)|aws-access-key-id", raw))
        oidc = "id-token: write" in raw or (isinstance(perms, dict) and perms.get("id-token") == "write")
        if uses_keys and not oidc:
            find("NEW-CICD-NO-OIDC", name, f"{name}: long-lived AWS keys from GitHub secrets (no OIDC / id-token: write)", "P1", evidence=name, layer="cicd")
        applies = bool(re.search(r"terraform[^\n]*\bapply\b", raw))
        if applies and param("NEW-CICD-PR-APPLY.scope", "job") == "job":
            # job-aware: only jobs that contain the apply AND are not gated to push/main count
            def gated_off_pr(j):
                c = str(j.get("if", ""))
                return bool(re.search(r"github\.event_name\s*==\s*'push'|github\.ref\s*==\s*'refs/heads/", c)) and "pull_request" not in c
            applies = any(isinstance(j, dict) and re.search(r"terraform[^\n]*\bapply\b", yaml.safe_dump(j)) and not gated_off_pr(j)
                          for j in (d.get("jobs") or {}).values())
        if applies and (pr or prt):
            find("NEW-CICD-PR-APPLY", name, f"{name}: runs terraform apply on {'pull_request_target' if prt else 'pull_request'} (unreviewed code changes prod)", "P0", evidence=name, layer="cicd")
        unpinned = sorted({u for u in re.findall(r"uses:\s*([\w.-]+/[\w./-]+@[\w.-]+)", raw) if not re.search(r"@[0-9a-f]{40}$", u)})
        if unpinned:
            find("NEW-CICD-ACTION-PIN", name, f"{name}: actions not pinned to a commit SHA: {', '.join(unpinned)}", "P2", evidence=name, layer="cicd")
        if prt:
            if re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", raw) or "github.head_ref" in raw:
                find("NEW-CICD-PRT-HEAD", name, f"{name}: pull_request_target checks out the PR head and runs it (pwn request)", "P0", evidence=name, layer="cicd")
            sec = sorted(set(re.findall(r"secrets\.([A-Z0-9_]+)", raw)))
            if sec:
                find("NEW-CICD-FORK-SECRETS", name, f"{name}: pull_request_target job exposes secrets to fork PRs: {', '.join(sec)} (names only)", "P1", evidence=name, layer="cicd")

    # ---- Helm (repo side) ----
    for f in glob.glob(f"{repo}/**/helmfile*.y*ml", recursive=True) + glob.glob(f"{repo}/**/Chart.yaml", recursive=True):
        d = yaml.safe_load(open(f)) or {}
        bad = [r.get("url") for r in d.get("repositories", []) if str(r.get("url", "")).startswith("http://") or not r.get("verify")]
        bad += [x.get("repository") for x in d.get("dependencies", []) if str(x.get("repository", "")).startswith("http://")]
        nover = [r["name"] for r in d.get("releases", []) if "/" in str(r.get("chart", "")) and not str(r.get("chart")).startswith(".") and not r.get("version")]
        nover += [x["name"] for x in d.get("dependencies", []) if str(x.get("version", "*")) in ("*", "", "latest") or x.get("version", "").startswith(">")]
        if bad or nover:
            find("NEW-HELM-REPO", os.path.basename(f), f"{rel(f)}: unverified/plain-http chart repos {bad} and unpinned charts {nover}", "P2", evidence=rel(f), layer="helm")


    # ---- Supply chain: Docker / deps / AI agent skills & MCP (static, free OSS path) ----
    PIPE_SHELL = re.compile(r"(?:sudo\s+)?(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", re.I)
    FROM_RE = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+\S+)?\s*$", re.I | re.M)
    ADD_REMOTE = re.compile(r"^\s*ADD\s+(https?://\S+)", re.I | re.M)
    PIP_UNPIN = re.compile(r"\b(?:pip3?|python\s+-m\s+pip)\s+install\b([^\n\\]+)", re.I)
    NPM_UNPIN = re.compile(r"\bnpm\s+install\b([^\n\\]+)", re.I)
    EOL_BASE = {
        "python": {"2.7", "3.4", "3.5", "3.6", "3.7", "3.8"},
        "node": {"8", "10", "12", "14", "16", "18"},
        "nodejs": {"8", "10", "12", "14", "16", "18"},
        "ubuntu": {"16.04", "18.04", "20.04"},
        "debian": {"9", "10", "stretch", "buster"},
        "centos": {"6", "7", "8"},
    }
    INJECT_MARKERS = re.compile(
        r"ignore\s+(all\s+)?previous\s+instructions|disregard\s+(all\s+)?prior|"
        r"<!--[^>]{0,200}(?:ignore|exfil|send\s+(?:the\s+)?(?:data|credentials|secrets)|https?://)[^>]{0,200}-->|"
        r"(?:exfil|send|post|upload)\b[^\n]{0,80}\bhttps?://|"
        r"(?:base64|b64)[^\n]{0,40}[A-Za-z0-9+/]{24,}={0,2}",
        re.I,
    )
    SECRET_ENV = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|openai|anthropic|aws[_-]?secret)", re.I)
    SKILL_GLOBS = [
        f"{repo}/AGENTS.md",
        f"{repo}/.cursor/rules/**/*",
        f"{repo}/.claude/skills/**/*",
        f"{repo}/.cursor/skills/**/*",
        f"{repo}/skills/**/*",
        f"{repo}/.codex/**/*",
    ]
    MCP_PATHS = [
        f"{repo}/.cursor/mcp.json",
        f"{repo}/.mcp.json",
        f"{repo}/claude_desktop_config.json",
        f"{repo}/.vscode/mcp.json",
    ]

    def walk_skill_files():
        seen = set()
        for g in SKILL_GLOBS:
            for f in glob.glob(g, recursive=True):
                if not os.path.isfile(f):
                    continue
                if f.endswith((".md", ".mdc", ".txt", ".sh", ".py", ".js", ".ts")) or f.endswith("SKILL.md"):
                    if f not in seen:
                        seen.add(f); yield f

    # Dockerfiles
    for df in sorted(set(glob.glob(f"{repo}/**/Dockerfile*", recursive=True))):
        if "/.terraform/" in df or "/node_modules/" in df:
            continue
        raw = open(df, encoding="utf-8", errors="replace").read()
        r = rel(df)
        floating, eol = [], []
        for m in FROM_RE.finditer(raw):
            ref = m.group(1)
            if ref.startswith("scratch"):
                continue
            has_digest = "@sha256:" in ref
            image = ref.split("@", 1)[0]
            name, _, tag = image.partition(":")
            short = name.split("/")[-1].lower()
            if not has_digest and (tag == "" or tag.lower() == "latest"):
                floating.append(ref)
            ver = re.match(r"^(\d+(?:\.\d+){0,2}|[a-z]+)", tag or "")
            major = (ver.group(1) if ver else "") or ""
            majors = {major}
            if re.match(r"^\d+\.\d+", major):
                majors.add(major.split(".")[0])
            for base, eol_set in EOL_BASE.items():
                if short == base or short.startswith(base):
                    if majors & eol_set or tag in eol_set:
                        eol.append(ref)
        if floating:
            find("NEW-DOCKER-FROM-PIN", "Dockerfile", f"{r}: FROM uses floating tag without @sha256 digest: {', '.join(floating)}", "P2", evidence=r, layer="supply")
        if eol:
            find("NEW-DOCKER-EOL-BASE", "Dockerfile", f"{r}: FROM uses EOL/old base image: {', '.join(eol)}", "P1", evidence=r, layer="supply")
        pipes = PIPE_SHELL.findall(raw)
        if pipes:
            find("NEW-DOCKER-PIPE-SHELL", "Dockerfile", f"{r}: pipe-to-shell in RUN ({len(pipes)} hit(s), e.g. curl|bash)", "P1", evidence=r, layer="supply")
        for am in ADD_REMOTE.finditer(raw):
            # BuildKit --checksum= is the safe form; a preceding CHECKSUM= env is not enough
            window_start = max(0, am.start() - 120)
            window = raw[window_start:am.end()]
            if "--checksum" not in window and not re.search(r"checksum\s*=\s*\S+", window, re.I):
                find("NEW-DOCKER-ADD-REMOTE", "Dockerfile", f"{r}: ADD from remote URL without checksum: {am.group(1)}", "P2", evidence=r, layer="supply")
                break
        for pm in PIP_UNPIN.finditer(raw):
            args = pm.group(1)
            if re.search(r"(^|\s)-r\s+\S+", args):
                continue
            pkgs = [t for t in re.split(r"\s+", args.strip()) if t and not t.startswith("-")]
            if any("==" not in p and ">=" not in p and "~=" not in p for p in pkgs):
                find("NEW-DOCKER-UNPINNED-INSTALL", "Dockerfile", f"{r}: pip install of unpinned package(s) not via requirements file: {' '.join(pkgs[:5])}", "P2", evidence=r, layer="supply")
                break
        for nm in NPM_UNPIN.finditer(raw):
            args = nm.group(1)
            if re.search(r"\bpackage(-lock)?\.json\b", args):
                continue
            pkgs = [t for t in re.split(r"\s+", args.strip()) if t and not t.startswith("-")]
            if pkgs and any("@" not in p.split("/")[-1] or p.endswith("@latest") for p in pkgs):
                find("NEW-DOCKER-UNPINNED-INSTALL", "Dockerfile", f"{r}: npm install of unpinned package(s): {' '.join(pkgs[:5])}", "P2", evidence=r, layer="supply")
                break
        # optional offline-ish CVE assist (never required; no plant; degrade if missing)
        if floating or eol:
            for tool in ("trivy", "grype"):
                if not shutil.which(tool):
                    continue
                try:
                    cmd = [tool, "config", df] if tool == "trivy" else [tool, "dockerfile", df]
                    # best-effort, short timeout, never fail the audit
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
                    if p.returncode not in (0, None) and (p.stdout or p.stderr):
                        find("NEW-DOCKER-CVE-OPTIONAL", "Dockerfile", f"{r}: {tool} reported issues on Dockerfile (optional offline assist)", "P3",
                             status="needs_validation", evidence=r, layer="supply")
                except Exception:
                    pass
                break

    # CI workflows: pipe-to-shell
    for name, (d, raw) in WF.items():
        if PIPE_SHELL.search(raw):
            find("NEW-CICD-PIPE-SHELL", name, f"{name}: pipe-to-shell (curl|bash / wget|sh) in a workflow step", "P1", evidence=name, layer="supply")

    # requirements.txt unpinned
    for req in sorted(glob.glob(f"{repo}/**/requirements*.txt", recursive=True)):
        if "/.terraform/" in req or "/node_modules/" in req:
            continue
        bad = []
        for line in open(req, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # bare package or VCS without pin
            if re.match(r"^[A-Za-z0-9_.-]+$", line) or (re.match(r"^[A-Za-z0-9_.-]+", line) and not re.search(r"(==|>=|<=|~=|!=|@)", line)):
                bad.append(line.split()[0] if line.split() else line)
        if bad:
            find("NEW-DEPS-UNPINNED", "requirements.txt", f"{rel(req)}: unpinned Python deps (no ==): {', '.join(bad[:8])}", "P2", evidence=rel(req), layer="supply")

    # package.json without lockfile
    for pj in sorted(glob.glob(f"{repo}/**/package.json", recursive=True)):
        if "/node_modules/" in pj or "/.terraform/" in pj:
            continue
        d = os.path.dirname(pj)
        locks = [x for x in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json") if os.path.isfile(os.path.join(d, x))]
        if not locks:
            find("NEW-DEPS-NO-LOCKFILE", "package.json", f"{rel(pj)}: package.json present but no lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml)", "P2", evidence=rel(pj), layer="supply")

    # Renovate / Dependabot update hygiene
    reno = None
    for cand in (f"{repo}/renovate.json", f"{repo}/renovate.json5", f"{repo}/.github/renovate.json"):
        if os.path.isfile(cand):
            reno = cand; break
    dep = None
    for cand in (f"{repo}/.github/dependabot.yml", f"{repo}/.github/dependabot.yaml"):
        if os.path.isfile(cand):
            dep = cand; break
    hygiene_ok = False
    res_name = "renovate.json"
    if reno:
        res_name = os.path.basename(reno)
        try:
            rd = yaml.safe_load(open(reno, encoding="utf-8")) or {}
        except Exception:
            rd = {}
        # Renovate: minimumReleaseAge or packageRules with minimumReleaseAge / internalChecksFilter
        txt = open(reno, encoding="utf-8").read()
        if re.search(r"minimumReleaseAge|internalChecksFilter\s*[:=]\s*[\"']strict", txt):
            hygiene_ok = True
    elif dep:
        res_name = os.path.basename(dep)
        txt = open(dep, encoding="utf-8").read()
        # dependabot has no first-class cooldown historically; treat presence alone as weak hygiene unless cooldown-days appears
        if re.search(r"cooldown-days|cooldown_days", txt, re.I):
            hygiene_ok = True
    else:
        res_name = "renovate.json"
    if not hygiene_ok:
        why = ("renovate/dependabot config missing" if not (reno or dep)
               else f"{rel(reno or dep)} present but no minimumReleaseAge / cooldown")
        find("NEW-DEPS-UPDATE-HYGIENE", res_name, f"Dependency update hygiene: {why}", "P3", evidence=res_name, layer="supply")

    # AI agent skills / rules
    for sf in walk_skill_files():
        try:
            txt = open(sf, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        base = os.path.basename(sf)
        if INJECT_MARKERS.search(txt):
            find("NEW-AGENT-PROMPT-INJECT", base if base != "install.sh" else "SKILL.md",
                 f"{rel(sf)}: agent skill/rule contains prompt-injection / exfil markers", "P0", evidence=rel(sf), layer="supply")
            # one finding per plant resource is enough; keep scanning other files for scripts
        if sf.endswith((".sh", ".py", ".js", ".ts")) and (PIPE_SHELL.search(txt) or re.search(r"\beval\s*\(|\bexec\s*\(", txt) or re.search(r"https?://\S*(exfil|evil|invalid)", txt, re.I)):
            find("NEW-AGENT-SKILL-SCRIPT", base, f"{rel(sf)}: skill-bundled script runs pipe-to-shell / eval / exfil URL", "P0", evidence=rel(sf), layer="supply")

    # MCP configs
    for mp in MCP_PATHS:
        if not os.path.isfile(mp):
            continue
        try:
            md = json.load(open(mp, encoding="utf-8"))
        except Exception:
            try:
                md = yaml.safe_load(open(mp, encoding="utf-8")) or {}
            except Exception:
                continue
        servers = md.get("mcpServers") or md.get("servers") or {}
        if not isinstance(servers, dict):
            continue
        unpinned, secrets, broad = [], [], []
        for sname, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            cmd = str(cfg.get("command", ""))
            args = cfg.get("args") or []
            args_s = " ".join(str(a) for a in args)
            joined = cmd + " " + args_s
            # unpinned npx/uvx/bunx
            if re.search(r"\b(npx|uvx|bunx)\b", joined):
                # pin forms: pkg@1.2.3, pkg==1.2.3, pkg@sha256:, git+...@<40hex>
                pkgs = []
                if cmd in ("npx", "uvx", "bunx"):
                    pkgs = [str(a) for a in args if not str(a).startswith("-") and not str(a).startswith(("/", ".", "~", "$"))]
                else:
                    pkgs = re.findall(r"\b(?:npx|uvx|bunx)\s+(?:-[^\s]+\s+)*(\S+)", joined)
                for pkg in pkgs:
                    if pkg.startswith("git+") or pkg.startswith("https://github.com/") or pkg.startswith("github:"):
                        if not re.search(r"@[0-9a-f]{40}$", pkg):
                            unpinned.append(f"{sname}:{pkg}")
                    elif pkg.endswith("@latest") or pkg == "latest":
                        unpinned.append(f"{sname}:{pkg}")
                    elif not re.search(r"@\d+\.\d+|==\d+\.\d+|@sha256:", pkg):
                        # bare package name with npx -y
                        if "-y" in args_s or cmd in ("uvx", "bunx"):
                            unpinned.append(f"{sname}:{pkg}")
            env = cfg.get("env") or {}
            if isinstance(env, dict):
                for ek, ev in env.items():
                    if SECRET_ENV.search(str(ek)) and str(ev).strip():
                        secrets.append(f"{sname}:{ek}")
            # broad filesystem roots in args
            for a in args:
                a = str(a)
                if a in ("/", "~", "${HOME}", "$HOME", "/home", "/Users", "C:\\", "C:/"):
                    broad.append(f"{sname}:{a}")
                elif re.fullmatch(r"/home/[^/]+/?", a) or re.fullmatch(r"/Users/[^/]+/?", a):
                    broad.append(f"{sname}:{a}")
        bn = "mcp.json"
        if unpinned:
            find("NEW-AGENT-MCP-PIN", bn, f"{rel(mp)}: MCP server(s) unpinned (npx/uvx @latest / bare / git without SHA): {', '.join(unpinned[:6])}", "P1", evidence=rel(mp), layer="supply")
        if secrets:
            find("NEW-AGENT-MCP-SECRETS", bn, f"{rel(mp)}: MCP env has hardcoded secret-like keys (values not shown): {', '.join(secrets[:6])}", "P1", evidence=rel(mp), layer="supply")
        if broad:
            find("NEW-AGENT-MCP-FS", bn, f"{rel(mp)}: MCP filesystem server granted broad root(s): {', '.join(broad[:6])}", "P2", evidence=rel(mp), layer="supply")



    return backend
