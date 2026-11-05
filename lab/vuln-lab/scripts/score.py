#!/usr/bin/env python3
"""Score a roqy-audit run against the vuln-lab ground truth.

Usage:
  python scripts/score.py findings.json                 # list of {check_id, severity, resource, title}
  python scripts/score.py report.md                     # markdown report (tables or bullets)
  python scripts/score.py findings.json --enable allow_public,foreign_account --disable instance
  python scripts/score.py findings.json --json out.json --fail-under 90
  python scripts/score.py merged.json --categories c19,c20,c21,c22,c23,c24,c25   # envelope only
  (several findings files: pass a JSON whose "findings" is the concatenation)

Detected  = a finding carries one of the plant's expected_check_ids AND names the plant's resource
            (absence plants with resource=account need only the check id).
Missed    = enabled plant with no matching finding.
Unmatched = findings that touch a roqy-lab resource but match no plant (likely false positive or
            a mis-labelled check id), plus findings with unknown check ids.
Exit code 1 if coverage < --fail-under (default 0 = never fail).
"""
import argparse, json, os, re, sys
try:
    import yaml
except ImportError:
    sys.exit("pip install pyyaml")

SEV_RE = re.compile(r"\b(P[0-3]|critical|high|medium|low|info)\b", re.I)
SEV_MAP = {"critical": "P0", "high": "P1", "medium": "P2", "low": "P3", "info": "P3"}
ID_RE = re.compile(r"\b(W\d{1,3}|NEW-[A-Z0-9-]+|[A-Z]{1,3}\d{1,3})\b")


def norm_sev(s):
    if not s:
        return None
    s = str(s).strip()
    return SEV_MAP.get(s.lower(), s.upper() if re.fullmatch(r"[Pp][0-3]", s) else None)


def load_findings(path):
    txt = open(path, encoding="utf-8").read()
    if path.endswith(".json"):
        data = json.loads(txt)
        if isinstance(data, dict):
            data = data.get("findings", [])
        out = []
        for f in data:
            out.append({"check_id": str(f.get("check_id", "")).strip(), "severity": norm_sev(f.get("severity")),
                        "resource": str(f.get("resource", "")), "title": str(f.get("title", "")),
                        "text": json.dumps(f, ensure_ascii=False)})
        return out
    # Markdown: every line (table row, bullet, heading) that contains a check id becomes a finding.
    out, last_heading = [], ""
    for line in txt.splitlines():
        if line.lstrip().startswith("#"):
            last_heading = line
        ids = ID_RE.findall(line)
        ids = [i for i in ids if i.startswith(("W", "NEW-")) or re.fullmatch(r"[A-Z]\d{1,3}", i)]
        if not ids:
            continue
        sev = SEV_RE.search(line) or SEV_RE.search(last_heading)
        for cid in dict.fromkeys(ids):
            out.append({"check_id": cid, "severity": norm_sev(sev.group(1)) if sev else None,
                        "resource": "", "title": line.strip()[:160], "text": line})
    return out


def mentions(f, token):
    t = token.lower()
    hay = (f["resource"] + " " + f["title"] + " " + f["text"]).lower()
    if t in hay:
        return True
    # tolerate random suffixes: "roqy-lab-llm-rag-data" matches "roqy-lab-llm-rag-data-a1b2c3"
    return bool(re.search(re.escape(t) + r"[-a-z0-9]*", hay))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("findings")
    ap.add_argument("--expected", default=os.path.join(os.path.dirname(__file__), "..", "EXPECTED-FINDINGS.yaml"))
    ap.add_argument("--enable", default="", help="comma list of extra conditions that were ON for this run")
    ap.add_argument("--disable", default="", help="comma list of default conditions that were OFF")
    ap.add_argument("--json", help="write machine-readable result here")
    ap.add_argument("--fail-under", type=float, default=0.0)
    ap.add_argument("--categories", default="", help="comma list: score only these categories (e.g. c19,c20,...,c25 for the envelope)")
    a = ap.parse_args()

    exp = yaml.safe_load(open(a.expected, encoding="utf-8"))
    on = set(exp["default_on_conditions"]) | {x for x in a.enable.split(",") if x}
    on -= {x for x in a.disable.split(",") if x}
    if "weak_trail" in on:
        on.discard("no_weak_trail")
    plants = [p for p in exp["plants"] if all(r in on for r in p["requires"])]
    if a.categories:
        cats = set(a.categories.split(","))
        plants = [p for p in plants if p["category"] in cats]
        exp["plants"] = [p for p in exp["plants"] if p["category"] in cats]
    skipped = [p for p in exp["plants"] if p not in plants]
    findings = load_findings(a.findings)
    # Maximum bipartite matching (Kuhn): one finding proves one plant, and the assignment no longer
    # depends on finding order (greedy let bedrock-logging-off steal the only W23 finding).
    def ok(p, f):
        return f["check_id"] in p["expected_check_ids"] and (p["resource"] == "account" or mentions(f, p["resource"]))
    cand = [[i for i, f in enumerate(findings) if ok(p, f)] for p in plants]
    owner = {}
    def aug(pi, seen):
        for i in cand[pi]:
            if i in seen:
                continue
            seen.add(i)
            if i not in owner or aug(owner[i], seen):
                owner[i] = pi
                return True
        return False
    # pass 1: only severity-correct edges (so two NEW-EKS-AUTH findings are not swapped between plants);
    # pass 2: any edge for plants still unmatched (augmenting paths keep pass-1 matches matched).
    full = cand
    cand = [[i for i in c if findings[i]["severity"] in (None, p["expected_severity"])] for c, p in zip(full, plants)]
    for pi in range(len(plants)):
        aug(pi, set())
    cand = full
    for pi in range(len(plants)):
        if pi not in set(owner.values()):
            aug(pi, set())
    match = {pi: i for i, pi in owner.items()}
    used = set(owner)
    rows = []
    for pi, p in enumerate(plants):
        if pi in match:
            f = findings[match[pi]]
            sev_ok = f["severity"] in (None, p["expected_severity"])
            rows.append((p, "DETECTED", f["check_id"], f["severity"] or "-", sev_ok))
        else:
            rows.append((p, "MISSED", "-", "-", None))

    known_ids = {c for p in exp["plants"] for c in p["expected_check_ids"]}
    unmatched = [f for i, f in enumerate(findings) if i not in used and
                 ("roqy-lab" in (f["resource"] + f["title"] + f["text"]).lower() or f["check_id"] not in known_ids)]

    det = sum(1 for r in rows if r[1] == "DETECTED")
    cov = 100.0 * det / len(rows) if rows else 0.0
    w = max(len(p["id"]) for p in plants) if plants else 10
    print(f"{'plant':<{w}}  {'cat':<6} {'status':<8} {'expected':<26} {'got':<24} sev(exp/got)")
    print("-" * (w + 80))
    for p, st, cid, sev, ok in rows:
        sev_s = f"{p['expected_severity']}/{sev}" + ("" if ok in (True, None) else "  <-- severity mismatch")
        print(f"{p['id']:<{w}}  {p['category']:<6} {st:<8} {','.join(p['expected_check_ids']):<26} {cid:<24} {sev_s}")
    print()
    by_cat = {}
    for p, st, *_ in rows:
        c = by_cat.setdefault(p["category"], [0, 0]); c[1] += 1; c[0] += st == "DETECTED"
    print("Per category: " + "  ".join(f"{k}:{v[0]}/{v[1]}" for k, v in sorted(by_cat.items())))
    new_needed = sorted({c for p, st, *_ in rows if st == "MISSED" for c in p["expected_check_ids"] if c.startswith("NEW-")})
    if new_needed:
        print("Missing checks to implement: " + ", ".join(new_needed))
    print(f"\nUnmatched / possible false positives: {len(unmatched)}")
    for f in unmatched[:40]:
        print(f"  [{f['check_id']}] {f['severity'] or '-'} {f['resource'] or ''} {f['title'][:100]}")
    print(f"\nSkipped plants (condition off): {len(skipped)}  ->  {', '.join(p['id'] for p in skipped)}")
    print(f"\nCOVERAGE: {det}/{len(rows)} = {cov:.1f}%   (findings parsed: {len(findings)})")
    if a.json:
        json.dump({"coverage_pct": round(cov, 1), "detected": det, "enabled": len(rows),
                   "missed": [p["id"] for p, st, *_ in rows if st == "MISSED"],
                   "severity_mismatch": [p["id"] for p, st, c, s, ok in rows if ok is False],
                   "unmatched": unmatched, "skipped": [p["id"] for p in skipped]}, open(a.json, "w"), indent=2)
    sys.exit(1 if cov < a.fail_under else 0)


if __name__ == "__main__":
    main()
