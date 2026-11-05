#!/usr/bin/env python3
"""Harness²-style improvement loop for roqy-audit, without Vertex AI.

  PROPOSE  proposer/propose.py (deterministic heuristics + pluggable LLM hook) sees ONLY sanitized feedback
  PROBE    probe.py runs the read-only audit executors on the lab variants, the hidden grader scores them
  COMPOSE  keep the candidates that improve the objective without raising FPs; re-verify the composition live;
           commit to surface/ (+ sync checks-v3.yaml), log to runs/ledger.jsonl

Usage: python3 loop.py [--iterations N] [--baseline-run runs/<id>/baseline]   (reuse a fresh live baseline)
"""
import argparse, copy, datetime, json, os, shutil, subprocess, sys, time, yaml
HERE = os.path.dirname(os.path.abspath(__file__))
SURFACE = os.path.join(HERE, "surface")
sys.path.insert(0, HERE)
from probe import CFG, probe  # noqa: E402  (paths in config.yaml resolved against the repo root)

SEVS = {"P0", "P1", "P2", "P3"}


def load_surface(d):
    return {f: yaml.safe_load(open(os.path.join(d, f))) for f in ("checks-overlay.yaml", "knob-catalog.yaml", "guardrails.yaml")}


def validate(e, catalog):
    k = e.get("kind")
    if k == "set_severity": return e.get("value") in SEVS and bool(e.get("check_id"))
    if k == "set_param": return e.get("param") in catalog and (e["value"] in catalog[e["param"]]["alternatives"] or e["value"] == catalog[e["param"]]["default"])
    if k == "set_disabled": return isinstance(e.get("value"), bool) and bool(e.get("check_id"))
    return False  # append_prompt / decision are never auto-applied by the deterministic executor


def guardrails_only_tightened(old, new):
    a, b = old["aws"], new["aws"]
    return (set(b["allowed_profiles"]) <= set(a["allowed_profiles"]) and set(a["denied_ops"]) <= set(b["denied_ops"])
            and set(a["denied_args"]) <= set(b["denied_args"]) and set(b["allowed_ops_extra"]) <= set(a["allowed_ops_extra"])
            and b["allowed_op_regex"] == a["allowed_op_regex"] and set(new["kubectl"]["allowed_verbs"]) <= set(old["kubectl"]["allowed_verbs"])
            and set(new["helm"]["allowed_verbs"]) <= set(old["helm"]["allowed_verbs"]))


def apply_edits(src, dst, edits):
    if os.path.abspath(src) != os.path.abspath(dst):
        shutil.copytree(src, dst, dirs_exist_ok=True)
    else:
        src = shutil.copytree(src, dst + ".prev", dirs_exist_ok=True)  # keep the pre-commit surface for the guardrail diff
    p = os.path.join(dst, "checks-overlay.yaml")
    ov = yaml.safe_load(open(p)) or {}
    ov.setdefault("checks", {}); ov.setdefault("params", {})
    for e in edits:
        if e["kind"] == "set_severity": ov["checks"].setdefault(e["check_id"], {})["severity"] = e["value"]
        elif e["kind"] == "set_disabled": ov["checks"].setdefault(e["check_id"], {})["disabled"] = e["value"]
        elif e["kind"] == "set_param": ov["params"][e["param"]] = e["value"]
    yaml.safe_dump(ov, open(p, "w"), sort_keys=False)
    old, new = load_surface(src)["guardrails.yaml"], load_surface(dst)["guardrails.yaml"]
    assert guardrails_only_tightened(old, new), "edit would loosen guardrails"
    return dst


def accepts(base, cand):
    return (cand["detected"] >= base["detected"] and cand["severity_mismatch"] <= base["severity_mismatch"]
            and cand["clean_fp"] <= base["clean_fp"] and cand["untriaged_unmatched"] <= base["untriaged_unmatched"]
            and cand["guard_violations"] == 0 and cand["objective"] > base["objective"])


def key(e):
    return (e["kind"], e.get("check_id") or e.get("param"))


def propose(fb_path, surface):
    p = subprocess.run([sys.executable, os.path.join(HERE, "proposer", "propose.py"), fb_path, surface, json.dumps(CFG.get("llm", {}))],
                       capture_output=True, text=True)
    if p.returncode != 0: raise SystemExit("proposer failed: " + p.stderr[-800:])
    return json.loads(p.stdout)


def sync_checks_yaml(edits, note):
    path = os.path.join(CFG["lab_run"], "checks-v3.yaml")
    doc = yaml.safe_load(open(path))
    ids = {c["id"]: c for c in doc["checks"]}
    for e in edits:
        if e["kind"] == "set_severity" and e["check_id"] in ids:
            c = ids[e["check_id"]]; c["harness_loop"] = f"{note}: severity {c.get('severity')} -> {e['value']}"; c["severity"] = e["value"]
    yaml.safe_dump(doc, open(path, "w"), sort_keys=False, allow_unicode=True, width=200)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--iterations", type=int, default=CFG["loop"]["max_iterations"])
    ap.add_argument("--baseline-run"); a = ap.parse_args()
    rid = datetime.datetime.now().strftime("%Y%m%d-%H%M%S"); R = os.path.join(HERE, "runs", rid); os.makedirs(R)
    ledger = open(os.path.join(HERE, "runs", "ledger.jsonl"), "a")
    report = [f"# harness-loop run {rid}\n"]
    if a.baseline_run:
        base_dir = a.baseline_run; pr = json.load(open(f"{base_dir}/probe-result.json")); base, fbp, scale = pr["summary"], pr["feedback"], pr["scale"]
    else:
        base_dir = f"{R}/it0-baseline"; t = time.time()
        base, fbp, scale = probe(SURFACE, base_dir, mode="live")
        print(f"baseline (live, {time.time()-t:.0f}s): {base}", flush=True)
    cache = f"{base_dir}/full/raw-core"
    report.append(f"## baseline (live)\n`{json.dumps(base)}`\n\nscale: `{json.dumps(scale)}`\n")
    for it in range(1, a.iterations + 1):
        cands = propose(fbp, SURFACE)
        catalog = load_surface(SURFACE)["knob-catalog.yaml"]
        auto = [e for e in cands if validate(e, catalog)]
        other = [e for e in cands if not validate(e, catalog)]
        print(f"iter {it}: {len(cands)} proposals, {len(auto)} auto-probeable", flush=True)
        report.append(f"## iteration {it}\n{len(cands)} proposals ({len(auto)} probed, {len(other)} decisions/prompt lines recorded only)\n")
        report.append("| # | edit | source | detected | sev_mismatch | clean_fp | untriaged | objective | verdict |\n|---|---|---|---|---|---|---|---|---|")
        results = []
        for i, e in enumerate(auto):
            cs = apply_edits(SURFACE, f"{R}/it{it}-c{i}/surface-in", [e])
            t = time.time()
            s, _, sc = probe(cs, f"{R}/it{it}-c{i}", mode=CFG["loop"]["candidate_probe_mode"], cache=cache)
            ok = accepts(base, s); results.append((e, s, ok))
            desc = f"{e['kind']} {e.get('check_id') or e.get('param')}={json.dumps(e['value'])[:40]}"
            report.append(f"| {i} | `{desc}` | {e['source']} | {s['detected']} | {s['severity_mismatch']} | {s['clean_fp']} | {s['untriaged_unmatched']} | {s['objective']} | {'ACCEPT' if ok else 'reject'} |")
            print(f"  c{i} {desc}: {s} -> {'ACCEPT' if ok else 'reject'} ({time.time()-t:.0f}s)", flush=True)
            ledger.write(json.dumps({"run": rid, "iter": it, "cand": i, "edit": e, "summary": s, "accepted": ok}) + "\n")
        for e in other:
            report.append(f"\n- recorded ({e['kind']}, {e['source']}): {e.get('text') or e.get('why')}")
        acc = {}
        for e, s, ok in results:
            if ok and (key(e) not in acc or s["objective"] > acc[key(e)][1]["objective"]): acc[key(e)] = (e, s)
        if not acc:
            report.append("\nno candidate improved the objective -> stop\n"); print("no improvement, stop"); break
        chosen = [v[0] for v in sorted(acc.values(), key=lambda v: -v[1]["objective"])]
        # COMPOSE: all chosen together, verified LIVE; if the composition regresses fall back to greedy add-one
        composed = []
        trial = chosen
        while trial:
            cs = apply_edits(SURFACE, f"{R}/it{it}-compose/surface-in", trial)
            s, f2, sc2 = probe(cs, f"{R}/it{it}-compose", mode=CFG["loop"]["final_probe_mode"])
            if accepts(base, s): composed = trial; break
            trial = trial[:-1]
        if not composed:
            report.append("\ncomposition failed live verification -> nothing committed\n"); break
        prev = load_surface(SURFACE)["checks-overlay.yaml"]
        apply_edits(SURFACE, SURFACE, composed)
        ov = yaml.safe_load(open(f"{SURFACE}/checks-overlay.yaml")); ov["version"] = (prev.get("version") or 0) + 1
        yaml.safe_dump(ov, open(f"{SURFACE}/checks-overlay.yaml", "w"), sort_keys=False)
        sync_checks_yaml(composed, f"harness-loop {rid} it{it}")
        report.append(f"\n**composed + verified live:** {[key(e) for e in composed]}\n\nbefore `{json.dumps(base)}`\n\nafter  `{json.dumps(s)}`\n\nscale after: `{json.dumps(sc2)}`\n")
        ledger.write(json.dumps({"run": rid, "iter": it, "committed": composed, "before": base, "after": s, "overlay_version": ov["version"]}) + "\n")
        print(f"iter {it} committed {[key(e) for e in composed]}: {base['objective']} -> {s['objective']}", flush=True)
        base, fbp, cache = s, f2, f"{R}/it{it}-compose/full/raw-core"
    open(f"{R}/REPORT.md", "w").write("\n".join(report) + "\n")
    print("report:", f"{R}/REPORT.md")


if __name__ == "__main__":
    main()
