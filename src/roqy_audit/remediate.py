"""Rank a few repo-only edits by how many P0/P1 chains they close.

A fix is one idea applied to every file that needs it (for example a
permissions block in two workflows). Patches are unified diffs of those
files. We do not invent commit SHAs, image digests, or cloud role ARNs,
and a diff that would print a secret is dropped.
"""
import difflib, os, re

from roqy_audit.chains import build_chains

_SECRET = re.compile(
    r"AKIA[0-9A-Z]{8,}|ASIA[0-9A-Z]{8,}|ghp_[A-Za-z0-9]|github_pat_|sk_live_|"
    r"aws_secret_access_key\s*[:=]\s*\S+|BEGIN [A-Z ]*PRIVATE KEY",
    re.I,
)

# One idea, the check ids it removes. Earlier entries win ties when the
# chain counts match, so a patch we can actually write beats a prose-only fix.
_IDEAS = [
    {
        "id": "permissions-block",
        "title": "Add a least-privilege permissions block",
        "check_ids": ["NEW-CICD-PERMS"],
        "why": "These CI chains stay open because the workflow token is write-all or left at the default. contents: read removes that leg. Pinning actions is still worth doing, but it is not what closes the chain.",
    },
    {
        "id": "stop-pr-apply",
        "title": "Stop Terraform apply on pull requests",
        "check_ids": ["NEW-CICD-PR-APPLY"],
        "why": "Apply-on-pull-request is the deploy step in the chain. Gate apply to a push on the default branch. This report does not rewrite the job, because a wrong if: would still deploy.",
    },
    {
        "id": "drop-pr-head-checkout",
        "title": "Stop checking out pull-request head code",
        "check_ids": ["NEW-CICD-PRT-HEAD"],
        "why": "pull_request_target only becomes a takeover when the job checks out the PR head and then runs it. Check out the base ref instead. The workflow is not rewritten here, so a comment bot that only reads the head ref keeps working.",
    },
    {
        "id": "pin-actions",
        "title": "Pin GitHub Actions to a commit SHA",
        "check_ids": ["NEW-CICD-ACTION-PIN"],
        "why": "Unpinned actions are the shared leg of the CI chains. Look up the current tag's commit and pin that SHA. This report does not invent one.",
    },
    {
        "id": "remove-pipe-shell",
        "title": "Remove pipe-to-shell from the image build",
        "check_ids": ["NEW-DOCKER-PIPE-SHELL", "NEW-CICD-PIPE-SHELL"],
        "why": "The build-time chain needs a curl|bash or wget|sh step. Delete that RUN or workflow step and install from a file you already review. The line is not rewritten automatically.",
    },
]


def _scope(f):
    ev = str(f.get("evidence") or "").split(":")[0]
    res = str(f.get("resource") or "")
    if ev.endswith((".yml", ".yaml", ".tf")) or ev.endswith("Dockerfile") or "/" in ev:
        return ev
    if res.endswith((".yml", ".yaml")):
        return res
    return ev or res or "repo"


def chain_instances(findings):
    """One chain per rule per file, so two workflows are two chains, not one blob."""
    groups = {}
    owned = []
    for i, f in enumerate(findings):
        if f.get("tool", "roqy") != "roqy":
            continue
        groups.setdefault(_scope(f), []).append(i)
        owned.append(i)
    out = []
    for scope, idxs in groups.items():
        subset = [findings[i] for i in idxs]
        for chain in build_chains(subset):
            for step in chain["steps"]:
                step["index"] = idxs[step["index"]]
            chain["scope"] = scope
            chain["key"] = f"{chain['id']}@{scope}"
            out.append(chain)
    return out


def _locate(root, finding):
    ev = str(finding.get("evidence") or "").split(":")[0]
    res = str(finding.get("resource") or "")
    names = []
    for n in (ev, res):
        if n and n not in names:
            names.append(n)
    for name in names:
        for cand in (os.path.join(root, name), os.path.join(root, ".github", "workflows", name)):
            if os.path.isfile(cand):
                return cand
    return None


def _udiff(old, new, rel):
    diff = "".join(difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile=f"a/{rel}",
        tofile=f"b/{rel}",
        n=2,
    ))
    if not diff or _SECRET.search(diff):
        return None
    return diff


def _patch_permissions(text):
    write_all = re.compile(r"(?m)^permissions:\s*write-all\s*$")
    if write_all.search(text):
        return write_all.sub("permissions:\n  contents: read", text, count=1)
    if re.search(r"(?m)^permissions:", text):
        return None
    block = "permissions:\n  contents: read\n"
    name = re.search(r"(?m)^name:.*\n", text)
    if name:
        return text[:name.end()] + block + text[name.end():]
    return block + text


def _patches(root, findings):
    patches = []
    seen = set()
    for f in findings:
        if f.get("check_id") != "NEW-CICD-PERMS":
            continue
        path = _locate(root, f)
        if not path:
            continue
        rel = os.path.relpath(path, root)
        if rel in seen:
            continue
        seen.add(rel)
        old = open(path, encoding="utf-8").read()
        new = _patch_permissions(old)
        if new is None or new == old:
            continue
        diff = _udiff(old, new, rel)
        if diff:
            patches.append({"path": rel, "diff": diff})
    return patches


def _broken(before, after):
    left = {c["key"] for c in after}
    return [c for c in before if c["key"] not in left and c.get("severity") in ("P0", "P1")]


def _rank_key(broken, has_patch):
    p0 = sum(1 for c in broken if c["severity"] == "P0")
    p1 = sum(1 for c in broken if c["severity"] == "P1")
    return (p0 + p1, p0, p1, 1 if has_patch else 0)


def recommend(findings, root, limit=3):
    """Top fixes. Each one is scored by the P0/P1 chains that disappear if its findings are removed."""
    roqy = [f for f in findings if f.get("tool", "roqy") == "roqy"]
    before = [c for c in chain_instances(roqy) if c.get("severity") in ("P0", "P1")]
    if not before:
        return []
    index = {id(f): i for i, f in enumerate(roqy)}
    ideas = []
    for idea in _IDEAS:
        owned = [f for f in roqy if f.get("check_id") in idea["check_ids"]]
        if not owned:
            continue
        ideas.append((idea, owned))
    chosen = []
    covered = set()
    while ideas and len(chosen) < limit and len(covered) < len(before):
        ranked = []
        for idea, owned in ideas:
            drop = {id(f) for f in owned}
            remain = [f for f in roqy if id(f) not in drop]
            gone = _broken(before, chain_instances(remain))
            gone = [c for c in gone if c["key"] not in covered]
            patches = _patches(root, owned) if idea["id"] == "permissions-block" else []
            ranked.append((_rank_key(gone, bool(patches)), idea, owned, gone, patches))
        ranked.sort(key=lambda row: row[0], reverse=True)
        best = ranked[0]
        if best[0][0] == 0:
            break
        _key, idea, owned, gone, patches = best
        covered.update(c["key"] for c in gone)
        ideas = [(i, o) for i, o in ideas if i["id"] != idea["id"]]
        chosen.append({
            "id": idea["id"],
            "title": idea["title"],
            "why": idea["why"],
            "p0_chains": sum(1 for c in gone if c["severity"] == "P0"),
            "p1_chains": sum(1 for c in gone if c["severity"] == "P1"),
            "chains": [{"id": c["id"], "title": c["title"], "severity": c["severity"], "scope": c.get("scope", "")} for c in gone],
            "findings": [{"check_id": f.get("check_id"), "resource": f.get("resource"), "severity": f.get("severity")} for f in owned],
            "patches": patches,
        })
    return chosen


def render_markdown(fixes):
    lines = ["## How to break these chains", ""]
    if not fixes:
        lines.append("No P0 or P1 chain has a repo-only edit that closes it.")
        lines.append("")
        return "\n".join(lines)
    lines.append("The one to three edits below close the most P0/P1 chains. A patch is included only when the file in the repo is enough to write it. No cloud role, image digest, or secret is invented.")
    lines.append("")
    for n, fix in enumerate(fixes, 1):
        n_chains = fix["p0_chains"] + fix["p1_chains"]
        bits = []
        if fix["p0_chains"]:
            bits.append(f"{fix['p0_chains']} P0")
        if fix["p1_chains"]:
            bits.append(f"{fix['p1_chains']} P1")
        lines.append(f"### {n}. {fix['title']}")
        lines.append("")
        lines.append(f"Breaks {n_chains} chain{'s' if n_chains != 1 else ''} ({', '.join(bits)}).")
        for c in fix["chains"]:
            where = f" ({c['scope']})" if c.get("scope") else ""
            lines.append(f"- `{c['id']}` {c['title']}{where}")
        files = sorted({f["resource"] for f in fix["findings"] if f.get("resource")})
        if files:
            lines.append("")
            lines.append("Findings removed: " + ", ".join(f"`{f['check_id']}` {f['resource']}" for f in fix["findings"][:8]) + ".")
        lines.append("")
        lines.append(fix["why"])
        lines.append("")
        if fix["patches"]:
            for p in fix["patches"]:
                lines.append(f"Patch `{p['path']}`:")
                lines.append("")
                lines.append("```diff")
                lines.append(p["diff"].rstrip("\n"))
                lines.append("```")
                lines.append("")
        else:
            lines.append("No patch is included: the safe edit needs a value that is not in this repo.")
            lines.append("")
    return "\n".join(lines)
