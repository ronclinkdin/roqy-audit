"""Explicit attack-chain rules. A chain fires only when every required check id is present."""

SEV_ORDER = ["P0", "P1", "P2", "P3"]

# each rule: id, title, severity, impact, fix_order, need (all of these check ids),
# also (extra ids included in steps when present)
RULES = [
    {
        "id": "ci-cloud-takeover",
        "title": "CI to cloud takeover",
        "severity": "P0",
        "impact": "An unreviewed pull request can run a workflow whose token can write to the repo or deploy, using an unpinned action and a long-lived or overly broad cloud credential.",
        "fix_order": [
            "Stop applying Terraform from pull requests and from pull_request_target head checkouts.",
            "Replace long-lived AWS keys with a repo-scoped OIDC role.",
            "Pin every action to a full commit SHA and drop write-all token permissions.",
        ],
        "need": ["NEW-CICD-ACTION-PIN"],
        "need_any": ["NEW-CICD-PERMS", "NEW-CICD-FORK-SECRETS"],
        "need_any_2": ["NEW-CICD-NO-OIDC", "NEW-CICD-PR-APPLY", "NEW-CICD-PRT-HEAD", "NEW-CICD-FORK-SECRETS"],
        "steps": ["NEW-CICD-ACTION-PIN", "NEW-CICD-PERMS", "NEW-CICD-FORK-SECRETS", "NEW-CICD-NO-OIDC", "NEW-CICD-PR-APPLY", "NEW-CICD-PRT-HEAD"],
    },
    {
        "id": "build-time-code-injection",
        "title": "Build-time code injection",
        "severity": "P1",
        "impact": "The image build downloads and executes a remote script, and the base image or packages are not pinned, so a later rebuild can run different code.",
        "fix_order": [
            "Remove pipe-to-shell (curl|bash, wget|sh) from Dockerfiles and workflows.",
            "Pin base images with a digest and stop using EOL tags.",
            "Install dependencies from a lockfile, not floating names.",
        ],
        "need": ["NEW-DOCKER-PIPE-SHELL"],
        "need_any": ["NEW-DOCKER-FROM-PIN", "NEW-DOCKER-EOL-BASE", "NEW-DOCKER-UNPINNED-INSTALL", "NEW-CICD-PIPE-SHELL"],
        "steps": ["NEW-DOCKER-PIPE-SHELL", "NEW-CICD-PIPE-SHELL", "NEW-DOCKER-FROM-PIN", "NEW-DOCKER-EOL-BASE", "NEW-DOCKER-UNPINNED-INSTALL", "NEW-DOCKER-ADD-REMOTE"],
    },
    {
        "id": "agent-tool-compromise",
        "title": "Agent tool compromise",
        "severity": "P0",
        "impact": "An agent skill or MCP server can pull a new tool release at launch, and that tool is handed a secret or a filesystem root that reaches the host.",
        "fix_order": [
            "Pin MCP packages to a version or commit SHA. Do not use npx -y or @latest.",
            "Remove literal secrets from MCP env. Pass them from the operator's secret store.",
            "Narrow filesystem MCP roots to the project directory, not / or the home directory.",
        ],
        "need": ["NEW-AGENT-MCP-PIN"],
        "need_any": ["NEW-AGENT-MCP-SECRETS", "NEW-AGENT-MCP-FS"],
        "steps": ["NEW-AGENT-MCP-PIN", "NEW-AGENT-MCP-SECRETS", "NEW-AGENT-MCP-FS", "NEW-AGENT-PROMPT-INJECT", "NEW-AGENT-SKILL-SCRIPT"],
    },
    {
        "id": "secret-direct-access",
        "title": "Leaked secret gives direct access",
        "severity": "P1",
        "impact": "A credential is written into Terraform state or a committed default. Anyone who can read that file can use the credential.",
        "fix_order": [
            "Remove hardcoded secret defaults and rotate the value.",
            "Keep secret material out of state, or encrypt state and restrict who can read the state bucket.",
        ],
        "need_any": ["NEW-TF-STATE-SECRETS", "NEW-TF-HARDCODED-SECRET"],
        "steps": ["NEW-TF-HARDCODED-SECRET", "NEW-TF-STATE-SECRETS", "NEW-TF-STATE-LOCK"],
    },
]


def _has(ids, rule):
    if rule.get("need") and not set(rule["need"]) <= ids:
        return False
    if rule.get("need_any") and not (ids & set(rule["need_any"])):
        return False
    if rule.get("need_any_2") and not (ids & set(rule["need_any_2"])):
        return False
    return True


def build_chains(findings):
    by = {}
    for i, f in enumerate(findings):
        by.setdefault(f.get("check_id"), []).append(i)
    ids = set(by)
    chains = []
    for rule in RULES:
        if not _has(ids, rule):
            continue
        steps = []
        for cid in rule["steps"]:
            for idx in by.get(cid, []):
                f = findings[idx]
                steps.append({"check_id": cid, "index": idx, "resource": f.get("resource", ""), "title": f.get("title", "")})
        if not steps:
            continue
        chains.append({
            "id": rule["id"],
            "title": rule["title"],
            "severity": rule["severity"],
            "impact": rule["impact"],
            "fix_order": list(rule["fix_order"]),
            "steps": steps,
        })
    chains.sort(key=lambda c: SEV_ORDER.index(c["severity"]) if c["severity"] in SEV_ORDER else 9)
    return chains
