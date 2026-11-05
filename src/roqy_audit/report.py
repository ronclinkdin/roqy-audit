"""Markdown, JSON, and SARIF renderers."""
import json

from roqy_audit import __version__
from roqy_audit.chains import SEV_ORDER
from roqy_audit.soc2 import DISCLAIMER, for_check

_SARIF_LEVEL = {"P0": "error", "P1": "error", "P2": "warning", "P3": "note"}


def annotate(findings):
    for f in findings:
        f["soc2"] = for_check(f.get("check_id", ""), f.get("tool", "roqy"))
        f.setdefault("tool", "roqy")
        f.setdefault("status", "confirmed")
    return findings


def to_json(payload):
    return json.dumps(payload, indent=1, default=str)


def to_markdown(payload):
    chains = payload.get("chains") or []
    findings = payload.get("findings") or []
    tools = payload.get("tools") or []
    lines = [
        f"# roqy-audit scan: {payload.get('target', '.')}",
        "",
        f"{len(findings)} findings, {len(chains)} attack chains. {DISCLAIMER}",
        "",
        "## Attack chains",
        "",
    ]
    if not chains:
        lines.append("No chain rule matched. Findings below are still individual issues.")
        lines.append("")
    for i, c in enumerate(chains[:10], 1):
        lines.append(f"### {i}. {c['title']} ({c['severity']})")
        lines.append("")
        lines.append(c["impact"])
        lines.append("")
        lines.append("Steps:")
        for s in c["steps"][:8]:
            lines.append(f"- `{s['check_id']}` {s.get('resource', '')} — {s.get('title', '')[:140]}")
        lines.append("")
        lines.append("Fix in this order:")
        for n, step in enumerate(c["fix_order"], 1):
            lines.append(f"{n}. {step}")
        lines.append("")
    lines.append("## Top findings")
    lines.append("")
    ranked = sorted(findings, key=lambda f: SEV_ORDER.index(f["severity"]) if f.get("severity") in SEV_ORDER else 9)
    if not ranked:
        lines.append("No findings.")
        lines.append("")
    for f in ranked[:12]:
        soc = ", ".join(f.get("soc2") or [])
        lines.append(f"- **{f.get('severity')}** `{f.get('check_id')}` {f.get('resource')} — {f.get('title', '')[:160]} ({soc})")
    if len(ranked) > 12:
        lines.append(f"- … {len(ranked) - 12} more in the JSON report.")
    lines.append("")
    lines.append("## Tools run / not run")
    lines.append("")
    for t in tools:
        lines.append(f"- `{t['name']}`: {t['status']} — {t.get('detail', '')}")
    lines.append("")
    lines.append(DISCLAIMER)
    lines.append("")
    return "\n".join(lines)


def to_sarif(payload):
    findings = payload.get("findings") or []
    rules = {}
    results = []
    for i, f in enumerate(findings):
        rid = f.get("check_id") or f"F{i+1}"
        rules.setdefault(rid, {
            "id": rid,
            "shortDescription": {"text": rid},
            "fullDescription": {"text": (f.get("title") or rid)[:400]},
            "help": {"text": DISCLAIMER},
            "properties": {"soc2": f.get("soc2") or [], "tags": ["security", "roqy-audit"]},
        })
        loc = f.get("evidence") or f.get("resource") or payload.get("target") or "."
        results.append({
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f.get("severity"), "warning"),
            "message": {"text": f.get("title") or rid},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(loc).lstrip("./")},
                }
            }],
            "properties": {"severity": f.get("severity"), "soc2": f.get("soc2") or [], "tool": f.get("tool", "roqy")},
        })
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "roqy-audit", "version": __version__, "informationUri": "https://roqy.io", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=1)


def fails(findings, chains, fail_on):
    if not fail_on or fail_on == "none":
        return False
    if fail_on not in SEV_ORDER:
        raise SystemExit(f"unknown --fail-on {fail_on}")
    limit = SEV_ORDER.index(fail_on)
    for f in findings:
        sev = f.get("severity")
        if sev in SEV_ORDER and SEV_ORDER.index(sev) <= limit:
            return True
    for c in chains:
        sev = c.get("severity")
        if sev in SEV_ORDER and SEV_ORDER.index(sev) <= limit:
            return True
    return False
