#!/usr/bin/env python3
"""roqy-audit skill_risk: PRE-INSTALL risk report for an AI-agent skill, rules pack, plugin or MCP server.

Static by construction (same contract as audit_envelope.py c26/c27):
  * Reads files only. Never installs, builds, imports or executes anything from the target.
  * Symlinks are never followed (a malicious repo could point a link at ~/.ssh).
  * Evidence snippets are truncated and secret-looking values are masked.
  * Network is OFF by default; --online adds read-only registry metadata (npm / PyPI JSON) and GitHub repo metadata.
  * Findings describe observable PATTERNS, not intent. "high" = "read this before installing", never "malicious".

Usage:
  python3 skill_risk.py PATH [--name owner/repo] [--kind skill|mcp|auto] [--meta meta.json] [--online] [--json out.json]
Exit code: 0 always (report tool), unless the path does not exist (2).
"""
import argparse, base64, json, os, re, subprocess, sys, time, urllib.request, datetime as dt

VERSION = "0.1"
SKIP_DIRS = {".git", "node_modules", "dist", "build", "out", ".next", "vendor", "__pycache__", ".venv", "venv", "site-packages",
             "coverage", ".turbo", ".cache", "target", "bower_components", ".yarn"}
TEXT_EXT = (".md", ".mdc", ".mdx", ".txt", ".rst", ".yaml", ".yml", ".json", ".toml", ".sh", ".bash", ".zsh", ".py", ".js", ".mjs",
            ".cjs", ".ts", ".tsx", ".jsx", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".go", ".rs", ".cfg", ".ini", ".html", ".xml")
CODE_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".ps1", ".psm1", ".bat", ".cmd", ".rb", ".go", ".rs")
MAX_BYTES = 1_500_000
WEIGHT = {"high": 3, "medium": 2, "low": 1, "info": 0}

# ---------- what counts as text the AGENT will read as instructions ----------
def is_agent_instruction(rel):
    b = os.path.basename(rel).lower()
    if b in ("skill.md", "claude.md", "agents.md", "gemini.md", ".cursorrules", ".windsurfrules", "copilot-instructions.md"):
        return True
    if b.endswith(".mdc"):
        return True
    parts = rel.lower().split(os.sep)
    return b.endswith(".md") and any(p in ("skills", "commands", "agents", "prompts", "rules", ".claude", ".cursor", ".codex", "instructions") for p in parts[:-1])

def is_test_or_example(rel):
    return bool(re.search(r"(^|/)(tests?|__tests__|spec|fixtures?|examples?|samples?|testdata|e2e|benchmarks?|evals?|demo|test-infrastructure)(/|$)|\.(test|spec)\.\w+$|_test\.(go|py)$|(^|/)test_[^/]+\.py$", rel, re.I))

def is_security_path(rel):
    return bool(re.search(r"pentest|red[-_]?team|offensive|payload|exploit|xss|sqli|ctf|bug[-_]?hunt|(^|/)hunt-|malware|reverse|security|threat|vuln|attack|waf|"
                          r"injection|poison|scanner|detector|guard|defen[cs]e|linter|supply[-_]chain|secret[-_]scan", rel, re.I))

def host_label(h):
    parts = [p for p in h.lower().split(".") if p and p not in ("www", "api", "app", "com", "org", "io", "net", "dev", "ai", "co", "cloud")]
    return parts[-1] if parts else ""

def integration_host(R, rel, host):
    """a telegram skill talking to telegram, an exa skill to exa.ai: first-party API, not egress to a stranger"""
    lab = re.sub(r"[^a-z0-9]", "", host_label(host))
    return bool(lab) and len(lab) >= 3 and (lab in re.sub(r"[^a-z0-9/]", "", rel.lower()) or lab in re.sub(r"[^a-z0-9/]", "", (R.name or "").lower()))

def inside_quotes(before_line):
    return before_line.count('"') % 2 == 1 or before_line.count("“") > before_line.count("”") or before_line.count("`") % 2 == 1

NEGATED = re.compile(r"\b(do\s+not|don'?t|never|avoid|no|not|without|instead\s+of|rather\s+than|unless|refuse|reject|flag|block|deny|disallow|dangerous)\b[^.\n]{0,60}$", re.I)
QUOTE_BEFORE = re.compile(r"[\"'`“‘«]\s*$")

def is_security_topic(text_head):
    """True when the skill's name or stated purpose is a security review, not merely when the body mentions attacks."""
    return bool(re.search(
        r"\b(red[- ]team|pentest|penetration test|offensive security|bug ?bount|ctf|malware analysis|reverse engineering|"
        r"exploit|vulnerability (scanner|research)|prompt injection|security (scanner|audit|review)|"
        r"secrets?[- ]hygiene|leaked credentials|exfiltration risks?|credential (scan|review|hygiene)|secret scanning)\b",
        text_head or "", re.I))


def stated_purpose(files, name=""):
    """Frontmatter name/description (and a root README), not the rest of the body.

    A hidden instruction must not reclassify the skill as a security topic.
    """
    bits = [name or ""]
    for rel, txt in files:
        base = os.path.basename(rel).lower()
        if base.startswith("readme") and rel.count(os.sep) == 0:
            bits.append(txt[:3000])
            continue
        if base not in ("skill.md", "agents.md", "claude.md") and not base.endswith(".mdc"):
            continue
        fm = re.match(r"^---\n(.*?)\n---", txt, re.S)
        if fm:
            bits.append(fm.group(1))
    return "\n".join(bits)

# ---------- patterns ----------
INJ_OVERRIDE = re.compile(r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding|system|developer)\s+"
                          r"(instructions?|prompts?|rules|messages|guidelines)", re.I)
# v2 (oss-scan FP fix): "do not tell the user TO run x" is advice, "silently"/"secretly" are ordinary prose
INJ_CONCEAL = re.compile(r"\b(do\s+not|don'?t|never)\s+(tell|inform|mention\s+(this\s+)?to|reveal\s+(this\s+)?to|notify|alert)\s+(the\s+)?user\s+(about|that|what|of)\b|"
                         r"\bwithout\s+(telling|informing|notifying|alerting)\s+(the\s+)?user\b|\b(hide|conceal|keep)\s+(this|it|these|them)\s+(secret\s+|hidden\s+)?from\s+the\s+user\b", re.I)
TOOL_POISON = re.compile(r"(?<![`\w])<\s*(IMPORTANT|SYSTEM|INSTRUCTIONS|HIDDEN)\s*>")  # case-sensitive; `<system>` placeholders are not tags
EXFIL_VERB = re.compile(r"\b(send|post|upload|exfiltrate|forward|transmit|submit|report|beacon|pipe)\b[^\n]{0,100}?(https?://[^\s)\"'>`]+)", re.I)
EXFIL_HOSTS = re.compile(r"(?<![A-Za-z0-9_-])(webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|trycloudflare\.com|interact\.sh|oast\.(pro|live|site|fun|me)|"
                         r"burpcollaborator\.net|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com|transfer\.sh|"
                         r"hastebin\.com|0x0\.st|file\.io|beeceptor\.com|canarytokens\.com)\b")  # case-sensitive (Toast.Provider != oast.pro)
SECRET_PATHS = re.compile(r"(~|\$HOME|%USERPROFILE%|/home/\w+|/Users/\w+)?/\.(ssh/(id_[a-z0-9]+|authorized_keys)|aws/credentials|"
                          r"kube/config|docker/config\.json|npmrc|pypirc|netrc|git-credentials|gnupg)\b|/etc/shadow\b|"
                          r"/Login Data\b|cookies\.sqlite|login\.keychain|wallet\.dat|\bid_rsa\b|\bid_ed25519\b")
SECRET_ACTION = re.compile(r"\b(read|cat|copy|upload|send|include|print|collect|exfil|attach|post|base64|encode|zip|tar)\b", re.I)
# v2: copying env for a child process is normal; serialising / piping ALL of it is the pattern
ENV_DUMP = re.compile(r"JSON\.stringify\(\s*process\.env\s*\)|json\.dumps\(\s*(dict\()?os\.environ|\bprintenv\s*\||\benv\s*\|\s*(curl|nc|base64)|"
                      r"str\(\s*os\.environ\s*\)")
SAFETY_OFF = re.compile(r"--dangerously-skip-permissions|\bbypassPermissions\b|--yolo\b|--dangerously-bypass-approvals-and-sandbox|"
                        r"\"?autoApprove\"?\s*:\s*\[\s*\"\*\"|\b(disable|turn\s+off|bypass|skip)\s+(all\s+)?(the\s+)?(safety|guardrails?|approvals?|"
                        r"confirmations?|permission\s+(checks?|prompts?)|sandbox)\b|\bnever\s+ask\s+(for\s+)?(permission|confirmation|approval)", re.I)
ZERO_WIDTH = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060-\u2064\u202a-\u202e\u2066-\u2069]|[\U000E0000-\U000E007F]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
COMMENT_IMPERATIVE = re.compile(r"\b(ignore|you must|always|never tell|send|upload|read|execute|run|curl|wget|http|assistant|agent|claude|ai)\b", re.I)
B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/=_-])")
PIPE_SHELL = re.compile(r"(?:curl|wget)\b[^\n|;]*https?://[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(iex|Invoke-Expression)\b|"
                        r"\b(ba)?sh\s+<\(\s*curl|\b(ba)?sh\s+-c\s+\"?\$\(\s*(curl|wget)", re.I)
REMOTE_EXEC = re.compile(r"\b(eval|exec|Function)\s*\(\s*(await\s+)?(fetch|requests\.get|urllib|http\.get|axios|atob|base64\.b64decode|"
                         r"Buffer\.from|zlib\.decompress|marshal\.loads|codecs\.decode)|\bexec\(\s*compile\(\s*(base64|zlib|requests|urllib)|python[3]?\s+-c\s+[\"']?\$\(\s*curl|"
                         r"\bnode\s+-e\s+[\"']?\$\(\s*curl", re.I)
OBFUSC = re.compile(r"(\\x[0-9a-f]{2}){40,}|String\.fromCharCode\(\s*\d+(\s*,\s*\d+){30,}|(_0x[0-9a-f]{4,6}.{0,40}){8,}|"
                    r"\bexec\(\s*marshal\.loads\(|\bexec\(\s*__import__\(|\bpyarmor_runtime\b|getattr\(__builtins__", re.I)
SHELL_EXEC = re.compile(r"child_process|\bexecSync\b|\bspawn(Sync)?\s*\(|\bsubprocess\.(run|Popen|call|check_output)\b|\bos\.system\(|"
                        r"\bshell\s*=\s*True|\bexec\.Command\(|std::process::Command|\bRuntime\.getRuntime\(\)\.exec", re.I)
FS_WRITE = re.compile(r"\bfs\.(promises\.)?(writeFile|appendFile|rm|unlink|rename)(Sync)?\b|\bopen\([^)]*[\"'][wa]\+?b?[\"']|\bshutil\.(rmtree|move)\b|"
                      r"\bos\.(remove|unlink|rename)\(|\bwrite_text\(|\bos\.WriteFile\b", re.I)
ENV_READ = re.compile(r"process\.env\.([A-Z][A-Z0-9_]{2,})|process\.env\[\s*[\"']([A-Z][A-Z0-9_]{2,})|os\.environ(?:\.get)?[\[(]\s*[\"']([A-Z][A-Z0-9_]{2,})|"
                      r"os\.getenv\(\s*[\"']([A-Z][A-Z0-9_]{2,})|os\.Getenv\(\s*\"([A-Z][A-Z0-9_]{2,})|env::var\(\s*\"([A-Z][A-Z0-9_]{2,})")
SECRET_NAME = re.compile(r"pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|credential|cookie|session", re.I)
URL = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(:\d+)?[^\s\"'`)<>]*")
BENIGN_HOSTS = re.compile(r"(^|\.)(github\.com|githubusercontent\.com|github\.io|npmjs\.(com|org)|pypi\.org|python\.org|nodejs\.org|"
                          r"modelcontextprotocol\.io|anthropic\.com|claude\.(ai|com)|openai\.com|example\.(com|org|net)|localhost|w3\.org|"
                          r"schema\.org|json-schema\.org|mozilla\.org|wikipedia\.org|shields\.io|creativecommons\.org|opensource\.org|"
                          r"apache\.org|mit-license\.org|readthedocs\.io|microsoft\.com|google\.com|googleapis\.com|stackoverflow\.com|"
                          r"youtube\.com|twitter\.com|x\.com|linkedin\.com|medium\.com|discord\.gg|npm\.im|unpkg\.com|jsdelivr\.net|"
                          r"docker\.com|docker\.io|amazonaws\.com|cloudflare\.com|vercel\.(app|com)|readme\.io|gitbook\.io)$", re.I)
TOOL_DEF = re.compile(r"\.(tool|registerTool|addTool)\s*\(|@(mcp|server|app)\.tool\b|\bTool\(\s*name\s*=|server\.setRequestHandler\(\s*CallToolRequestSchema|"
                      r"mcp\.NewTool\(|#\[tool\b")
INSTALL_LINE = re.compile(r"(?P<cmd>(?:claude\s+mcp\s+add[^\n`]*|npx\s+(?:-y\s+|--yes\s+)?[@\w./-]+[^\n`]*|uvx\s+[\w.@=-]+[^\n`]*|"
                          r"bunx\s+[@\w./-]+[^\n`]*|pipx?\s+install\s+[\w.@=<>~-]+[^\n`]*|npm\s+(?:i|install)\s+-g\s+[@\w./-]+[^\n`]*|"
                          r"/plugin\s+(?:marketplace\s+add|install)\s+[^\n`]+|git\s+clone\s+[^\n`]+|(?:curl|wget)[^\n`]*\|\s*(?:ba)?sh[^\n`]*|"
                          r"docker\s+run\s+[^\n`]+))")
POPULAR_PKGS = ["@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github", "@modelcontextprotocol/server-memory",
                "@modelcontextprotocol/server-everything", "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-puppeteer",
                "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/sdk", "@playwright/mcp", "@upstash/context7-mcp",
                "chrome-devtools-mcp", "firecrawl-mcp", "exa-mcp-server", "n8n-mcp", "mcp-server-fetch", "mcp-server-git", "mcp-server-time",
                "@browsermcp/mcp", "@agentdeskai/browser-tools-mcp", "@mobilenext/mobile-mcp", "@bytebase/dbhub", "@apify/actors-mcp-server",
                "mcp-remote", "fastmcp", "mcp"]
# v2: only AI-vendor names (google-ads / aws-xyz integrations are descriptive, not impersonation)
VENDOR_WORDS = {"anthropic": {"anthropics", "anthropic"}, "openai": {"openai"}, "official": set()}

def mask(s):
    s = re.sub(r"(sk-[A-Za-z0-9_-]{8})[A-Za-z0-9_-]+|(gh[pousr]_[A-Za-z0-9]{4})[A-Za-z0-9]+|(AKIA[A-Z0-9]{4})[A-Z0-9]+|(xox[abp]-[0-9]{3})[0-9A-Za-z-]+",
               lambda m: next(g for g in m.groups() if g) + "…[masked]", s)
    s = ZERO_WIDTH.sub(lambda m: f"<U+{ord(m.group(0)):04X}>", s)
    return s[:160]

def lev(a, b):
    if abs(len(a) - len(b)) > 3: return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]

class Report:
    def __init__(s, root, name, kind):
        s.root, s.name, s.kind = root, name, kind
        s.findings, s.perm, s.prov, s.pin = [], {"tools_declared": 0, "shell_exec_files": [], "fs_write_files": [], "env_vars": set(),
                                                  "allowed_tools": set(), "hooks": [], "egress_hosts": set()}, {}, {"install_commands": [], "unpinned": []}
        s.files_scanned = 0; s.skill_count = 0
    def add(s, cid, sev, why, rel="", line=0, ev="", cat=""):
        key = (cid, rel)
        same = [f for f in s.findings if (f["id"], f["file"]) == key]
        if same:
            same[0]["count"] += 1; return
        s.findings.append(dict(id=cid, severity=sev, category=cat, reason=why, file=rel, line=line, evidence=mask(ev.strip()), count=1))

def lines_of(text):
    return text.split("\n")

def line_no(text, pos):
    return text.count("\n", 0, pos) + 1

def in_code_fence(text, pos):
    return text.count("```", 0, pos) % 2 == 1

def walk(root):
    for d, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not os.path.islink(os.path.join(d, x))]
        for f in files:
            p = os.path.join(d, f)
            if os.path.islink(p): continue
            low = f.lower()
            if not (low.endswith(TEXT_EXT) or low in (".cursorrules", ".windsurfrules", "dockerfile", "makefile")): continue
            if low.endswith((".min.js", ".map", "-lock.json", ".lock")) or low in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"): continue
            try:
                if os.path.getsize(p) > MAX_BYTES: continue
                raw = open(p, "rb").read()
            except OSError:
                continue
            if b"\x00" in raw[:4096]: continue
            yield os.path.relpath(p, root), raw.decode("utf-8", errors="replace")

# ------------------------------------------------------------------ content (what the agent reads)
def scan_content(R, rel, txt, security_repo):
    agent = is_agent_instruction(rel)
    test = is_test_or_example(rel)
    md = rel.lower().endswith((".md", ".mdc", ".mdx", ".txt")) or os.path.basename(rel).startswith(".")
    code = rel.lower().endswith(CODE_EXT)
    # tool-description poisoning lives in code strings of MCP servers; agent instructions live in md
    reads_as_prompt = agent or (R.kind == "mcp" and code and not test)
    if not (reads_as_prompt or md): return
    secp = security_repo or is_security_path(rel)
    lower_sev = lambda sev, pos: ("low" if (test or secp or (md and in_code_fence(txt, pos)) or not agent and not code) else sev)
    def near_description(pos):  # MCP code: only tool/prompt description strings reach the model
        return bool(re.search(r"description|prompt|instructions", txt[max(0, pos - 300):pos], re.I))
    for m in re.finditer("(?:" + ZERO_WIDTH.pattern + ")+", txt):
        run = m.group(0); ch = run[0]
        if ch == "\u200d" and re.search(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", txt[max(0, m.start() - 2):m.end() + 2]): continue  # emoji ZWJ
        if ch in "\u200c\u200d\u200e\u200f" and len(run) < 3 and re.search(r"[\u0590-\u08ff\u0900-\u0DFF]", txt[max(0, m.start() - 3):m.end() + 3]): continue  # RTL/Indic script joiners & marks
        tag = any("\U000E0000" <= c <= "\U000E007F" for c in run)
        bidi = any(c in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" for c in run)
        sev = "high" if (tag or bidi or len(run) >= 4) and agent else ("medium" if agent and len(run) >= 3 else "low")
        if sev != "low" and not (tag or bidi) and (secp or test or (md and in_code_fence(txt, m.start()))): sev = "low"
        R.add("SR-HIDDEN-UNICODE", sev, "invisible/bidi/tag unicode characters in text the agent reads (can hide instructions from a human reviewer)",
              rel, line_no(txt, m.start()), txt[max(0, m.start() - 30):m.end() + 30], "content")
    if md:
        for m in HTML_COMMENT.finditer(txt):
            body = m.group(1)
            if len(body) > 20 and COMMENT_IMPERATIVE.search(body) and re.search(r"\b(ignore|disregard|you must|you are|instructions?|assistant|claude|the agent|the model|llm)\b", body, re.I) \
                    and re.search(r"\b(send|upload|post|read|run|execute|curl|wget|fetch|include|output|print|reveal|collect|exfil)\b", body, re.I) and not re.search(r"^\s*(prettier|markdownlint|eslint|toc|START|END|ALL-CONTRIBUTORS|BEGIN|"
                                                                                     r"lint|vale|omit in toc|badges?|header|footer|Generated|Copyright|SPDX|autogenerated|auto-generated|DO NOT EDIT)", body, re.I):
                R.add("SR-HIDDEN-COMMENT", "medium" if agent and not test and not secp and not re.search(r"noqa|example|e\.g\.", body, re.I) else "low",
                      "HTML comment with instruction-like text (invisible when rendered, visible to the agent)", rel, line_no(txt, m.start()), body[:120], "content")
    for rx, cid, sev, why in ((INJ_OVERRIDE, "SR-INJ-OVERRIDE", "high", "text tells the model to ignore/override prior instructions"),
                              (INJ_CONCEAL, "SR-INJ-CONCEAL", "high", "text tells the model to hide actions from the user"),
                              (TOOL_POISON, "SR-TOOL-POISON", "medium", "<IMPORTANT>/<SYSTEM>-style tag used to steer the model (tool-description poisoning pattern)"),
                              (SAFETY_OFF, "SR-SAFETY-OFF", "medium", "instructs to disable approvals / sandbox / permission prompts")):
        for m in rx.finditer(txt):
            if R.kind == "mcp" and code and not agent and not near_description(m.start()): continue
            ctx = txt[max(0, m.start() - 160):m.end() + 160]
            before = txt[max(0, m.start() - 80):m.start()]
            if cid in ("SR-INJ-OVERRIDE", "SR-INJ-CONCEAL", "SR-TOOL-POISON") and re.search(
                    r"\b(detect|detection|defen[cs]e|protect|example of|attack|attacker|malicious|injection|poison|guard|red flag|warn|beware|"
                    r"never follow|do not follow|don'?t follow|untrusted)\b", ctx, re.I):
                s = "low"  # describing / defending against the pattern, not using it
            elif QUOTE_BEFORE.search(before) or inside_quotes(before.split("\n")[-1]) or (cid in ("SR-SAFETY-OFF", "SR-INJ-CONCEAL") and NEGATED.search(before.split("\n")[-1])):
                s = "low"  # quoted example, or "do not use --yolo"
            else:
                s = lower_sev(sev, m.start())
            if cid == "SR-SAFETY-OFF" and (not agent or not re.search(r"dangerously|bypassPermissions|--yolo|autoApprove", m.group(0))): s = "low"  # generic "skip confirmation" CLI docs
            if cid == "SR-INJ-CONCEAL" and s == "high" and m.group(0).lower().startswith("without"): s = "medium"
            R.add(cid, s, why, rel, line_no(txt, m.start()), txt[max(0, m.start() - 40):m.end() + 60], "content")
    for m in EXFIL_VERB.finditer(txt):
        um = URL.match(m.group(2)); host = um.group(1) if um else ""
        if host and BENIGN_HOSTS.search(host): continue
        if not agent: continue
        line = txt[txt.rfind("\n", 0, m.start()) + 1: txt.find("\n", m.end()) if txt.find("\n", m.end()) > 0 else len(txt)]
        # v2: must be a data-moving verb about sensitive data; "report bugs [here](url)" is a human link
        if not re.search(r"\b(send|post|upload|exfiltrate|transmit|forward|pipe|beacon)\b", m.group(1), re.I): continue
        if not re.search(r"secret|credential|token|api[_ -]?key|password|cookie|ssh|\.env\b|env(ironment)? var|conversation|chat history|them\b", line, re.I): continue
        if re.search(r"(^|[`\s|])(POST|PUT|GET)\s+https?://", m.group(0)): continue  # HTTP-method API reference line
        if integration_host(R, rel, host): continue
        if re.search(r"\]\(\s*$", txt[max(0, m.end(2) - len(m.group(2)) - 2):m.end(2) - len(m.group(2))]): continue
        R.add("SR-EXFIL-INSTR", lower_sev("medium", m.start()), "instruction to send/upload data to an external URL", rel, line_no(txt, m.start()), m.group(0), "content")
    for m in SECRET_PATHS.finditer(txt):
        if not agent: break
        line = txt[txt.rfind("\n", 0, m.start()) + 1: m.end() + 120]
        sev = lower_sev("medium", m.start()) if re.search(r"\b(cat|print|upload|send|post|exfil\w*|collect|attach|include)\b", line, re.I) and not NEGATED.search(txt[max(0, m.start() - 80):m.start()]) else "low"
        R.add("SR-SECRET-PATHS", sev, "references credential/secret paths (ssh keys, cloud creds, browser stores)", rel,
              line_no(txt, m.start()), txt[max(0, m.start() - 40):m.end() + 40], "content")
    for m in B64_BLOB.finditer(txt):
        blob = m.group(0)
        if re.search(r"data:[\w/+.-]+;base64,$", txt[max(0, m.start() - 40):m.start()]): continue
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except Exception:
            continue
        printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in dec) / max(1, len(dec))
        if printable > 0.9:
            d = dec.decode("ascii", "replace")
            risky = bool(re.search(r"https?://|curl|wget|bash|eval|exec|ignore|instruction|ssh|token|secret", d, re.I))
            R.add("SR-B64-TEXT", "low" if secp or test else "high" if risky and (agent or code) else "medium" if agent else "low",
                  "base64 blob that decodes to readable text" + (" containing commands/URLs/instructions" if risky else ""), rel, line_no(txt, m.start()),
                  "decoded: " + d[:100], "content")

# ------------------------------------------------------------------ code
def scan_code(R, rel, txt, security_repo):
    low = rel.lower()
    test = is_test_or_example(rel)
    is_code = low.endswith(CODE_EXT) or os.path.basename(low) in ("dockerfile", "makefile")
    is_md = low.endswith((".md", ".mdc", ".mdx"))
    if is_code:
        for m in PIPE_SHELL.finditer(txt):
            if re.match(r"\s*(#|//|\*)", txt[txt.rfind("\n", 0, m.start()) + 1:m.start()]): continue  # commented out
            R.add("SR-PIPE-SHELL", "low" if test or is_security_path(rel) else "medium", "bundled script downloads and pipes a remote script into a shell", rel,
                  line_no(txt, m.start()), m.group(0), "code")
    if not is_code: return
    for m in REMOTE_EXEC.finditer(txt):
        R.add("SR-REMOTE-EXEC", "low" if test else "high", "eval/exec of downloaded or decoded content", rel, line_no(txt, m.start()),
              txt[m.start():m.end() + 60], "code")
    for m in OBFUSC.finditer(txt):
        R.add("SR-OBFUSCATION", "low" if test else "high", "obfuscated code (hex/charcode arrays, marshal, packers)", rel, line_no(txt, m.start()),
              txt[m.start():m.start() + 80], "code")
        break
    long_lines = [i for i, l in enumerate(lines_of(txt), 1) if len(l) > 4000]
    if long_lines and not re.search(r"(bundle|vendor|generated|\.d\.ts$)", low):
        R.add("SR-MINIFIED", "low", "very long single-line code in a non-vendored source file (hard to review)", rel, long_lines[0], "", "code")
    for m in EXFIL_HOSTS.finditer(txt):
        integration = integration_host(R, rel, m.group(0).split("/")[0])
        line_start = txt.rfind("\n", 0, m.start()) + 1
        line_end = txt.find("\n", m.end())
        line = txt[line_start: line_end if line_end >= 0 else len(txt)]
        window = txt[max(0, m.start() - 160):m.end() + 80]
        # A URL inside CLI help, a docstring, or a comment is not a network call.
        if re.search(r"\bhelp\s*=|description\s*=|\busage:|--help\b|argparse", window, re.I):
            continue
        if re.match(r"\s*(#|//|\*|\"\"\"|''')", line):
            continue
        ctx = "\n".join(txt[:m.end()].splitlines()[-4:])
        if not re.search(r"\b(fetch|axios|requests\.|urllib|urlopen|http\.(?:get|post|request)|got\(|curl|wget|net\.Dial|http\.Client|XMLHttpRequest)\b", ctx, re.I):
            continue
        R.add("SR-EXFIL-HOST", "low" if test or security_repo or is_security_path(rel) or integration else "high", "code references a request-capture / paste / webhook endpoint often used for data egress",
              rel, line_no(txt, m.start()), txt[max(0, m.start() - 40):m.end() + 40], "code")
    for m in ENV_DUMP.finditer(txt):
        R.add("SR-ENV-DUMP", "low" if test or is_security_path(rel) else "medium", "reads the whole environment (all env vars, incl. secrets) rather than named vars", rel,
              line_no(txt, m.start()), txt[max(0, m.start() - 30):m.end() + 40], "code")
    if not test:
        if SHELL_EXEC.search(txt): R.perm["shell_exec_files"].append(rel)
        if FS_WRITE.search(txt): R.perm["fs_write_files"].append(rel)
        for g in ENV_READ.findall(txt):
            n = next(x for x in g if x)
            R.perm["env_vars"].add(n)
        R.perm["tools_declared"] += len(TOOL_DEF.findall(txt))
        for m in URL.finditer(txt):
            h = m.group(1).lower()
            if not BENIGN_HOSTS.search(h) and not h.endswith((".svg", ".png")):
                R.perm["egress_hosts"].add(h)
            if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h) and not h.startswith(("127.", "0.", "10.", "192.168.", "169.254.", "172.")):
                R.add("SR-RAW-IP", "low", "hard-coded public IP endpoint in code", rel, line_no(txt, m.start()), m.group(0), "code")
        for m in SECRET_PATHS.finditer(txt):
            ln = txt[txt.rfind("\n", 0, m.start()) + 1: txt.find("\n", m.end()) if txt.find("\n", m.end()) > 0 else len(txt)]
            reads = bool(re.search(r"readFile|read_text|read_bytes|open\(|\bcat\s|fs\.read|createReadStream|ReadFile|upload|send|post", ln, re.I))
            if os.path.basename(low) == "dockerfile" or re.match(r"\s*(#|//|\*)", ln): continue
            R.add("SR-CODE-SECRET-PATHS", "medium" if reads and not (security_repo or is_security_path(rel)) else "low", "code touches credential/secret paths", rel, line_no(txt, m.start()),
                  txt[max(0, m.start() - 40):m.end() + 40], "code")

def _is_mcp_config(rel):
    b = os.path.basename(rel).lower()
    if b in (".mcp.json", "mcp.json", "claude_desktop_config.json", "plugin.json", "marketplace.json"):
        return True
    return b.startswith("mcp") and b.endswith(".json")


def _mcp_launch(R, rel, sname, cfg):
    """@latest / npx / uvx and a filesystem root of / or $HOME, in any mcp*.json."""
    cmd = str(cfg.get("command") or "")
    args = [str(a) for a in (cfg.get("args") or [])]
    joined = (cmd + " " + " ".join(args)).strip()
    if re.search(r"\b(npx|uvx|bunx)\b", joined):
        if cmd in ("npx", "uvx", "bunx"):
            pkgs = [a for a in args if a and not a.startswith("-") and not a.startswith(("/", ".", "~", "$"))]
        else:
            pkgs = re.findall(r"\b(?:npx|uvx|bunx)\s+(?:-[^\s]+\s+)*(\S+)", joined)
        loose = []
        for pkg in pkgs:
            if pkg.endswith("@latest") or pkg == "latest":
                loose.append(pkg)
            elif not re.search(r"@\d+\.\d+|==\d+\.\d+|@sha256:", pkg) and ("-y" in args or "--yes" in args or cmd in ("uvx", "bunx")):
                loose.append(pkg)
        if loose:
            R.add("SR-UNPINNED-INSTALL", "medium",
                  "MCP server is launched with npx/uvx and no pinned version (" + ", ".join(loose[:4]) + ")",
                  rel, 1, f"{sname}: {' '.join(loose[:4])}", "pinning")
    broad = [a for a in args if a in ("/", "~", "${HOME}", "$HOME", "/home", "/Users", "C:\\", "C:/")
             or re.fullmatch(r"/home/[^/]+/?", a) or re.fullmatch(r"/Users/[^/]+/?", a)]
    if broad:
        R.add("SR-MCP-BROAD-FS", "high", "MCP server is granted a broad filesystem root",
              rel, 1, f"{sname}: {', '.join(broad[:4])}", "permissions")


def scan_manifests(R, rel, txt):
    b = os.path.basename(rel).lower()
    if is_test_or_example(rel): return
    if b == "package.json":
        try: d = json.loads(txt)
        except Exception: return
        if d.get("private"): return  # never published -> never installed by users
        for k in ("preinstall", "install", "postinstall"):
            v = (d.get("scripts") or {}).get(k)
            if v:
                net = bool(re.search(r"curl|wget|https?://|node\s+-e|\|\s*(ba)?sh", v))
                R.add("SR-INSTALL-HOOK", "high" if net else "medium", f"package.json `{k}` runs automatically on install", rel,
                      next((i for i, l in enumerate(lines_of(txt), 1) if f'"{k}"' in l), 0), f"{k}: {v}", "code")
    if b == "setup.py":
        if re.search(r"cmdclass\s*=|urlopen|requests\.|subprocess|os\.system", txt):
            m = re.search(r"cmdclass\s*=|urlopen|requests\.|subprocess|os\.system", txt)
            R.add("SR-SETUP-PY-EXEC", "medium", "setup.py runs custom code at install time (custom cmdclass / subprocess / network)", rel, line_no(txt, m.start()),
                  txt[m.start():m.start() + 80], "code")
    if b in ("settings.json", "settings.local.json", "hooks.json") and ("/.claude" in "/" + rel or "hooks" in rel.lower()):
        try: d = json.loads(txt)
        except Exception: d = {}
        hooks = d.get("hooks") if isinstance(d, dict) else None
        if isinstance(hooks, dict) and hooks:
            cmds = re.findall(r'"command"\s*:\s*"([^"]+)"', json.dumps(hooks))
            R.perm["hooks"] += [f"{rel}:{e}" for e in hooks]
            net = [c for c in cmds if re.search(r"curl|wget|https?://|nc\s|\|\s*(ba)?sh", c)]
            dev_only = rel.startswith(".claude" + os.sep) and R.kind == "mcp"  # contributor settings of an MCP repo are not installed by users
            formatter_only = cmds and all(re.match(r"^\s*(npx\s+)?(prettier|eslint|black|ruff|gofmt|terraform\s+fmt|rustfmt|biome)\b", c) for c in cmds)
            R.add("SR-AUTO-HOOKS", "high" if net else "low" if dev_only or formatter_only else "medium", f"auto-run hooks on agent events ({', '.join(list(hooks)[:5])}): commands run without a per-call prompt",
                  rel, 1, (net or cmds or [""])[0], "permissions")
        perms = (d.get("permissions") or {}) if isinstance(d, dict) else {}
        if isinstance(d, dict) and d.get("enableAllProjectMcpServers") is True:
            R.add("SR-MCP-AUTOTRUST", "medium", "settings auto-enable every MCP server listed in the project .mcp.json (a PR can add one)", rel, 1, "enableAllProjectMcpServers: true", "permissions")
        if isinstance(perms, dict) and (perms.get("defaultMode") == "bypassPermissions" or any(a in ("Bash", "Bash(*)", "*") for a in perms.get("allow", []) or [])):
            R.add("SR-BROAD-ALLOW", "medium", "shipped settings pre-approve unrestricted Bash / bypass permission prompts", rel, 1, json.dumps(perms)[:120], "permissions")
    if b == "skill.md" or b.endswith(".mdc"):
        R.skill_count += b == "skill.md"
        fm = re.match(r"^---\n(.*?)\n---", txt, re.S)
        if fm:
            at = re.search(r"^allowed-tools:\s*(.+(?:\n\s+-.*)*)", fm.group(1), re.M)
            if at:
                tools = re.findall(r"[\w*]+(?:\([^)]*\))?", at.group(1))
                R.perm["allowed_tools"].update(tools)
                if any(t in ("Bash", "Bash(*)", "*") for t in tools):
                    R.add("SR-SKILL-BASH", "low", "skill frontmatter pre-allows unrestricted Bash", rel, 2, at.group(0)[:100], "permissions")
    if _is_mcp_config(rel):
        try: d = json.loads(txt)
        except Exception: return
        servers = d.get("mcpServers") or d.get("servers") or {}
        if isinstance(servers, dict):
            for sname, cfg in servers.items():
                if not isinstance(cfg, dict): continue
                _mcp_launch(R, rel, sname, cfg)
                for ek, ev in (cfg.get("env") or {}).items():
                    if SECRET_NAME.search(ek) and ev and not re.match(r"^\$\{?|^<|^your|^YOUR|^xxx|^\.\.\.|^sk-\.\.\.", str(ev)):
                        R.add("SR-MCP-SECRET-LITERAL", "medium", "MCP config ships a literal value for a secret-like env var (value not shown)", rel, 1, f"{sname}.env.{ek}", "permissions")

# ------------------------------------------------------------------ pinning: what install command does the README recommend?
def scan_install(R, rel, txt):
    b = os.path.basename(rel).lower()
    if not (b.startswith("readme") or b in ("install.md", "installation.md", "getting-started.md", "setup.md", "quickstart.md")): return
    if is_test_or_example(rel) or rel.count(os.sep) > 2: return
    for m in INSTALL_LINE.finditer(txt):
        c = m.group("cmd").strip()[:200]
        if c in R.pin["install_commands"]: continue
        R.pin["install_commands"].append(c)
        why = None
        if re.search(r"(curl|wget)[^|]*\|\s*(ba)?sh", c): why = "pipe-to-shell installer (runs whatever the URL serves at install time)"
        elif re.search(r"\bnpx\s+(-y\s+|--yes\s+)?", c):
            pk = re.search(r"\bnpx\s+(?:-y\s+|--yes\s+)?([@\w./-]+)", c).group(1)
            if pk.endswith("@latest") or not re.search(r".@\d", pk): why = f"npx {pk} without a pinned version (each launch may pull a new release)"
        elif re.search(r"\b(uvx|bunx)\s+", c):
            pk = re.search(r"\b(?:uvx|bunx)\s+(?:--from\s+)?([\w.@=/-]+)", c)
            if pk and not re.search(r"==\d|@\d", pk.group(1)): why = f"{pk.group(1)} via uvx/bunx without a pinned version"
        elif re.search(r"/plugin\s+(marketplace\s+add|install)", c) and not re.search(r"#[0-9a-f]{7,40}|@v?\d", c):
            why = "plugin/marketplace install tracks the default branch (updates land without review)"
        elif re.search(r"\bgit\s+clone\b", c) and not re.search(r"--branch\s+v?\d|-b\s+v?\d|@[0-9a-f]{7,40}", c):
            why = "git clone of the default branch (no tag/SHA)"
        elif re.search(r"\bpipx?\s+install\b", c) and not re.search(r"==\d|-r\s|-e\s|\.\s*$|\.\[", c):
            why = "pip install without ==version"
        elif re.search(r"\bnpm\s+(i|install)\s+-g", c) and not re.search(r"@\d", c):
            why = "global npm install without version"
        elif re.search(r"\bdocker\s+run\b", c) and re.search(r"(\s|/)[\w.-]+/[\w.-]+(:latest)?(\s|$)", c) and not re.search(r"@sha256:|:\d|:v\d", c):
            why = "docker run of an image without a version tag or digest"
        if why:
            R.pin["unpinned"].append(c)
            R.add("SR-UNPINNED-INSTALL", "medium" if "pipe-to-shell" in why else "low", "recommended install is unpinned: " + why, rel, line_no(txt, m.start()), c, "pinning")

# ------------------------------------------------------------------ provenance
def git_provenance(root):
    g = lambda *a: subprocess.run(["git", "-C", root, *a], capture_output=True, text=True, timeout=120).stdout
    try:
        if not os.path.isdir(os.path.join(root, ".git")): return {}
        shallow = os.path.isfile(os.path.join(root, ".git", "shallow"))
        log = g("log", "--format=%ae|%an|%ct|%G?").strip().splitlines()
        if not log: return {}
        emails = {l.split("|")[0].lower() for l in log}
        names = {l.split("|")[1] for l in log if "[bot]" not in l and "noreply@github.com" != l.split("|")[0]}
        ts = [int(l.split("|")[2]) for l in log]
        tags = [t for t in g("tag", "-l").split() if t]
        # signed = has a gpgsig header; %G? would need keys, so read raw headers of last 50 commits
        raw = g("log", "-50", "--format=%H")
        signed = 0
        for h in raw.split()[:50]:
            if "gpgsig" in g("cat-file", "commit", h): signed += 1
        now = time.time()
        return dict(commits=len(log), shallow=shallow, authors=len(names), author_emails=len(emails), first_commit_days=round((now - min(ts)) / 86400),
                    last_commit_days=round((now - max(ts)) / 86400), tags=len(tags), signed_recent_commits=f"{signed}/{min(50, len(log))}",
                    commits_last_30d=sum(t > now - 30 * 86400 for t in ts))
    except Exception as e:
        return {"error": str(e)[:100]}

def get_json(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "roqy-skill-risk/0.1", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)

def registry_meta(root, online, install_cmds=()):
    """npm / PyPI metadata for the package(s) this repo publishes. Read-only JSON GETs, no tarball download."""
    out = []
    pkgs = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".") and not is_test_or_example(os.path.relpath(os.path.join(d, x), root))]
        if os.path.relpath(d, root).count(os.sep) > 2: dirs[:] = []
        if "package.json" in files:
            try:
                pj = json.load(open(os.path.join(d, "package.json")))
                if pj.get("name") and not pj.get("private"): pkgs.append(("npm", pj["name"], pj.get("version"), os.path.relpath(d, root)))
            except Exception: pass
        if "pyproject.toml" in files:
            m = re.search(r'^\s*name\s*=\s*"([^"]+)"', open(os.path.join(d, "pyproject.toml"), errors="replace").read(), re.M)
            if m: pkgs.append(("pypi", m.group(1), None, os.path.relpath(d, root)))
    for eco, name, ver, where in pkgs[:8]:
        rec = any(re.search(rf"(^|[\s/]){re.escape(name)}(@|==|\s|$)", c) for c in install_cmds)
        info = dict(ecosystem=eco, name=name, path=where, recommended=rec)
        # typosquat-like proximity to popular names (offline)
        near = [p for p in POPULAR_PKGS if p != name and lev(name.lower(), p.lower()) <= 2 and len(name) > 4]
        if near: info["near_popular"] = near
        if online and (rec or where == "."):
            try:
                if eco == "npm":
                    j = get_json(f"https://registry.npmjs.org/{name.replace('/', '%2F')}")
                    latest = (j.get("dist-tags") or {}).get("latest")
                    v = (j.get("versions") or {}).get(latest, {})
                    info.update(published=True, latest=latest, maintainers=len(j.get("maintainers") or []),
                                repo_url=((j.get("repository") or {}).get("url") if isinstance(j.get("repository"), dict) else j.get("repository")),
                                has_install_script=bool(v.get("hasInstallScript")), provenance=bool((v.get("dist") or {}).get("attestations")),
                                versions=len(j.get("versions") or {}), created=(j.get("time") or {}).get("created"))
                else:
                    j = get_json(f"https://pypi.org/pypi/{name}/json")
                    i = j.get("info") or {}
                    urls = " ".join(str(x) for x in (i.get("project_urls") or {}).values()) + " " + str(i.get("home_page") or "")
                    info.update(published=True, latest=i.get("version"), repo_url=urls.strip()[:200], versions=len(j.get("releases") or {}))
            except Exception as e:
                info.update(published=False, lookup=str(e)[:60])
        out.append(info)
    return out

def github_meta(name):
    try:
        j = get_json(f"https://api.github.com/repos/{name}")
        return dict(stars=j["stargazers_count"], forks=j["forks_count"], created_at=j["created_at"], pushed_at=j["pushed_at"],
                    owner_type=j["owner"]["type"], license=(j.get("license") or {}).get("spdx_id"), archived=j.get("archived"))
    except Exception as e:
        return {"error": str(e)[:80]}

def days_since(iso):
    try: return (dt.datetime.now(dt.timezone.utc) - dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))).days
    except Exception: return None

def assess_provenance(R, name):
    p = R.prov
    gh, gi = p.get("github", {}), p.get("git", {})
    stars, forks = gh.get("stars") or 0, gh.get("forks") or 0
    age = days_since(gh["created_at"]) if gh.get("created_at") else None
    if age is not None and stars:
        spd = stars / max(age, 1)
        p["stars_per_day"] = round(spd, 1)
        if age < 45 and stars >= 3000:
            R.add("SR-PROV-STAR-VELOCITY", "medium", f"{stars} stars in {age} days ({spd:.0f}/day): popularity arrived faster than review usually does", "", 0, "", "provenance")
    if gi.get("commits") is not None and not gi.get("shallow") and stars >= 1000 and gi["commits"] <= 5:
        R.add("SR-PROV-THIN-HISTORY", "medium", f"{stars} stars but only {gi['commits']} commit(s): little public development history to review", "", 0, "", "provenance")
    if stars >= 2000 and forks / max(stars, 1) > 0.25 and (age or 999) < 120:
        R.add("SR-PROV-FORK-RATIO", "low", f"unusual fork/star ratio ({forks}/{stars}) on a young repo", "", 0, "", "provenance")
    if gi.get("authors") == 1 and stars >= 1000:
        R.add("SR-PROV-SINGLE-AUTHOR", "low", "single author in history (no second reviewer visible)", "", 0, "", "provenance")
    if gi.get("tags") == 0 and not any(x.get("published") for x in p.get("registry", [])):
        R.add("SR-PROV-NO-RELEASES", "low", "no tags/releases: there is no version to pin to; installs track a moving branch", "", 0, "", "provenance")
    if gh.get("owner_age_days") is not None and gh["owner_age_days"] < 90:
        R.add("SR-PROV-NEW-OWNER", "medium", f"owner account is {gh['owner_age_days']} days old", "", 0, "", "provenance")
    if gh.get("pushed_at") and days_since(gh["pushed_at"]) > 365:
        R.add("SR-PROV-STALE", "low", "no pushes for >1 year (unpatched dependencies likely)", "", 0, "", "provenance")
    if gh.get("archived"):
        R.add("SR-PROV-ARCHIVED", "low", "repository is archived", "", 0, "", "provenance")
    owner, _, repo = (name or "/").partition("/")
    for w, owners in VENDOR_WORDS.items():
        if re.search(rf"(^|[-_.]){w}([-_.]|$)", repo.lower()) and owner.lower() not in owners:
            R.add("SR-PROV-VENDOR-NAME", "medium" if w != "official" else "low", f"repo name uses '{w}' but the owner is not that vendor's account (check it is not mistaken for an official package)",
                  "", 0, name, "provenance")
    for reg in p.get("registry", []):
        if reg.get("near_popular"):
            R.add("SR-PROV-TYPOSQUAT", "medium", f"package name {reg['name']} is 1-2 edits from popular {reg['near_popular'][:2]}", "", 0, reg["name"], "provenance")
        if reg.get("published") and reg.get("recommended") and reg.get("repo_url") and name and name.lower() not in str(reg["repo_url"]).lower():
            R.add("SR-PROV-REPO-MISMATCH", "medium", f"{reg['ecosystem']} package {reg['name']} points to a different source repo ({str(reg['repo_url'])[:80]})", "", 0, reg["name"], "provenance")
        if reg.get("has_install_script"):
            R.add("SR-PROV-REGISTRY-INSTALL-SCRIPT", "medium", f"published npm {reg['name']}@{reg.get('latest')} declares an install script", "", 0, reg["name"], "provenance")

# ------------------------------------------------------------------ scoring
def _combo_exfil(findings):
    """Secret-path plus an exfil instruction in the same skill is high, even without an install hook."""
    live = {f["id"] for f in findings if f["severity"] in ("high", "medium")}
    secret = bool(live & {"SR-SECRET-PATHS", "SR-CODE-SECRET-PATHS"})
    exfil = bool(live & {"SR-EXFIL-INSTR", "SR-EXFIL-HOST"})
    return secret and exfil


def summarize(R):
    sev = [f["severity"] for f in R.findings]
    hi = sev.count("high"); med = sev.count("medium")
    score = sum(WEIGHT[s] for s in sev)
    perm = R.perm
    broad = bool(perm["shell_exec_files"]) and R.kind == "mcp"
    risk = "high" if hi or _combo_exfil(R.findings) else "medium" if (med >= 2 or (med and broad)) else "medium" if med else "low"
    reasons = sorted(R.findings, key=lambda f: -WEIGHT[f["severity"]])
    top = []
    for f in reasons:
        t = f["reason"].split(" (")[0]
        if f["severity"] in ("high", "medium") and t not in top: top.append(t)
    caps = []
    if perm["shell_exec_files"]: caps.append("runs shell commands")
    if perm["fs_write_files"]: caps.append("writes/deletes files")
    sec_env = sorted(e for e in perm["env_vars"] if SECRET_NAME.search(e))
    if sec_env: caps.append(f"reads secrets from env ({', '.join(sec_env[:3])}{'…' if len(sec_env) > 3 else ''})")
    if perm["hooks"]: caps.append("installs auto-run hooks")
    eg = sorted(perm["egress_hosts"])
    if eg: caps.append(f"talks to {len(eg)} external host(s)")
    unp = "install command is not version-pinned" if R.pin["unpinned"] else ""
    head = {"high": "⚠ Review before installing", "medium": "Caution", "low": "No high-risk patterns found"}[risk]
    parts = [f"{head}: {R.name or os.path.basename(R.root)}."]
    if top: parts.append("; ".join(top[:3]) + ".")
    if caps: parts.append("Capabilities: " + ", ".join(caps) + ".")
    if unp: parts.append("The recommended " + unp + "; pin a version/SHA.")
    parts.append("Patterns are observations, not proof of intent.")
    return risk, score, " ".join(parts)

def assess(root, name=None, kind="auto", meta=None, online=False):
    root = os.path.abspath(root)
    R = Report(root, name, kind)
    files = list(walk(root))
    if kind == "auto":
        mcpish = sum(1 for rel, t in files if rel.lower().endswith(CODE_EXT) and re.search(r"modelcontextprotocol|FastMCP|mcp\.server|mcp-go|rmcp", t))
        R.kind = "mcp" if mcpish else "skill"
    security_repo = is_security_topic(stated_purpose(files, name))
    for rel, txt in files:
        R.files_scanned += 1
        scan_content(R, rel, txt, security_repo)
        scan_code(R, rel, txt, security_repo)
        scan_manifests(R, rel, txt)
        scan_install(R, rel, txt)
    R.prov["git"] = git_provenance(root)
    R.prov["github"] = dict(meta or {})
    if online and name and not meta: R.prov["github"] = github_meta(name)
    R.prov["registry"] = registry_meta(root, online, R.pin["install_commands"])
    assess_provenance(R, name)
    # Security-topic skills (pentest writeups, detection examples) mention attack text on purpose.
    # Content-only markers are down-weighted. Code-execution patterns (category "code") stay weighted.
    if security_repo:
        for f in R.findings:
            # Prose in a security skill (credentials, exfil, ignore-previous) is the subject, not an instruction to the agent.
            if f["category"] == "content" and f["severity"] in ("high", "medium"):
                f["severity"] = "low"
                f["reason"] += " (down-weighted: security-topic content)"
    risk, score, warn = summarize(R)
    if security_repo:
        warn += " security_topic: content-only markers were down-weighted; code-execution patterns were not."
    perm = {k: (sorted(v) if isinstance(v, set) else v) for k, v in R.perm.items()}
    perm["shell_exec_files"] = perm["shell_exec_files"][:15]; perm["fs_write_files"] = perm["fs_write_files"][:15]
    perm["egress_hosts"] = perm["egress_hosts"][:40]; perm["env_vars"] = perm["env_vars"][:60]
    return dict(tool="roqy-skill-risk", version=VERSION, item=name or os.path.basename(root), kind=R.kind, security_topic=security_repo,
                files_scanned=R.files_scanned, skills=R.skill_count, risk=risk, score=score, warning=warn,
                counts={s: sum(f["severity"] == s for f in R.findings) for s in ("high", "medium", "low")},
                findings=sorted(R.findings, key=lambda f: (-WEIGHT[f["severity"]], f["id"], f["file"])),
                permissions=perm, pinning=R.pin, provenance=R.prov)

def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("path"); ap.add_argument("--name"); ap.add_argument("--kind", default="auto", choices=["auto", "skill", "mcp"])
    ap.add_argument("--meta", help="JSON with github metadata (stars, forks, created_at, pushed_at, owner_type, owner_age_days)")
    ap.add_argument("--online", action="store_true", help="read-only registry + GitHub metadata lookups")
    ap.add_argument("--json"); ap.add_argument("-q", action="store_true")
    a = ap.parse_args()
    if not os.path.isdir(a.path): print("no such dir", file=sys.stderr); sys.exit(2)
    meta = json.load(open(a.meta)) if a.meta else None
    r = assess(a.path, a.name, a.kind, meta, a.online)
    if a.json: json.dump(r, open(a.json, "w"), indent=1, default=str)
    if not a.q:
        print(f"[{r['risk'].upper()}] {r['item']} ({r['kind']}, {r['files_scanned']} files) score={r['score']} {r['counts']}")
        for f in r["findings"][:25]:
            if f["severity"] == "low": continue
            print(f"  {f['severity']:6} {f['id']:24} {f['file']}:{f['line']}  {f['reason'][:70]}  | {f['evidence'][:90]}")
        print("  WARNING:", r["warning"])

if __name__ == "__main__":
    main()
