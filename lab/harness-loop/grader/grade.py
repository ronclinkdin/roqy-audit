#!/usr/bin/env python3
"""Hidden grader. The ONLY harness component that reads EXPECTED-FINDINGS.yaml (via score.py).
Writes:
  <run>/private/grade.json   full detail (plant ids, resources)  -> composer + humans only
  <run>/feedback.json        sanitized view for the proposer: per-category scores, opaque miss tokens
                             mapped to check ids, severity-mismatch check ids (got only), FP counts per check.
"""
import argparse, hashlib, json, os, re, secrets, subprocess, sys, yaml
HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.abspath(os.path.join(HERE, "..", ".."))
SCORE = os.path.join(LAB, "vuln-lab", "scripts", "score.py")
EXPECTED = os.path.join(LAB, "vuln-lab", "EXPECTED-FINDINGS.yaml")
SALT_F = os.path.join(HERE, ".salt")


def salt():
    if not os.path.exists(SALT_F):
        open(SALT_F, "w").write(secrets.token_hex(16)); os.chmod(SALT_F, 0o600)
    return open(SALT_F).read().strip()


def token(pid):
    return "m-" + hashlib.sha256((salt() + pid).encode()).hexdigest()[:8]


def triaged(f, rules):
    hay = (f.get("resource", "") + " " + f.get("title", "")).lower()
    for r in rules:
        if f.get("check_id") == r["check_id"] and r["resource"].lower() in hay and (not r.get("title_re") or re.search(r["title_re"], f.get("title", ""), re.I)):
            return r
    return None


def grade(run, variant):
    os.makedirs(f"{run}/private", exist_ok=True)
    out = {"variant": variant["name"], "parts": {}}
    exp = yaml.safe_load(open(EXPECTED))
    plants = {p["id"]: p for p in exp["plants"]}
    rules = yaml.safe_load(open(os.path.join(HERE, "known-unplanted.yaml"))) or []
    fb = {"variant": variant["name"], "categories": {}, "misses": [], "severity_mismatch": [], "untriaged_unmatched_by_check": {},
          "clean_fp_by_check": {}, "permission_gaps": [], "scale": {}}
    if variant.get("score"):
        merged = f"{run}/findings-merged.json"
        args = [sys.executable, SCORE, merged, "--json", f"{run}/private/score.json"] + variant["score"].get("args", [])
        txt = subprocess.run(args, capture_output=True, text=True).stdout
        open(f"{run}/private/score.txt", "w").write(txt)
        sc = json.load(open(f"{run}/private/score.json"))
        cats = re.search(r"Per category: (.*)", txt).group(1).split()
        fb["categories"] = {c.split(":")[0]: c.split(":")[1] for c in cats}
        fb["misses"] = [{"token": token(pid), "category": plants[pid]["category"], "check_ids": plants[pid]["expected_check_ids"]} for pid in sc["missed"]]
        # severity mismatch: which check, what it emitted. NOT the expected value.
        for line in txt.splitlines():
            if "severity mismatch" in line:
                parts = line.split()
                pid, got = parts[0], parts[4]
                fb["severity_mismatch"].append({"token": token(pid), "check_id": got, "got": parts[5].split("/")[1]})
        unt = [f for f in sc["unmatched"] if not triaged(f, rules)]
        for f in unt:
            fb["untriaged_unmatched_by_check"][f["check_id"]] = fb["untriaged_unmatched_by_check"].get(f["check_id"], 0) + 1
        out["parts"]["lab"] = {"detected": sc["detected"], "enabled": sc["enabled"], "coverage_pct": sc["coverage_pct"], "missed": sc["missed"],
                               "severity_mismatch": sc["severity_mismatch"], "unmatched": len(sc["unmatched"]),
                               "untriaged_unmatched": [(f["check_id"], f["resource"], f["title"][:120]) for f in unt],
                               "triaged_true_positive_unplanted": len(sc["unmatched"]) - len(unt)}
    for cv in variant.get("clean_parts", []):
        p = f"{run}/{cv}.json"
        if not os.path.exists(p): continue
        fs = json.load(open(p)).get("findings", [])
        out["parts"][cv] = {"false_positives": [(f["check_id"], f["resource"], f["title"][:120]) for f in fs]}
        for f in fs:
            fb["clean_fp_by_check"][f["check_id"]] = fb["clean_fp_by_check"].get(f["check_id"], 0) + 1
    m = json.load(open(f"{run}/metrics.json")) if os.path.exists(f"{run}/metrics.json") else {}
    fb["permission_gaps"] = m.get("permission_gaps", [])
    fb["scale"] = {k: m.get(k) for k in ("wall_s", "api_calls_live", "api_calls_replay", "k8s_calls", "regions")}
    lab = out["parts"].get("lab", {})
    out["summary"] = {"detected": lab.get("detected", 0), "enabled": lab.get("enabled", 0),
                      "severity_mismatch": len(lab.get("severity_mismatch", [])), "untriaged_unmatched": len(lab.get("untriaged_unmatched", [])),
                      "triaged_true_positive_unplanted": lab.get("triaged_true_positive_unplanted", 0),
                      "clean_fp": sum(len(v.get("false_positives", [])) for k, v in out["parts"].items() if k != "lab"),
                      "guard_violations": m.get("guard_violations", 0)}
    s = out["summary"]
    s["objective"] = 10 * s["detected"] - 3 * s["severity_mismatch"] - 5 * s["clean_fp"] - 2 * s["untriaged_unmatched"] - 50 * s["guard_violations"]
    fb["summary"] = {k: s[k] for k in ("detected", "enabled", "severity_mismatch", "untriaged_unmatched", "clean_fp", "guard_violations")}
    # leak check: nothing plant-identifying may reach the proposer
    blob = json.dumps(fb).lower()
    for cid in sorted({c for p in plants.values() for c in p["expected_check_ids"]} | set(re.findall(r'"((?:new-|w)[a-z0-9-]+)"', blob)), key=len, reverse=True):
        blob = blob.replace(cid.lower(), "<cid>")   # check ids are allowed; a plant id that is a substring of one is not a leak
    leaks = [pid for pid, p in plants.items() if pid.lower() in blob or (p["resource"] != "account" and p["resource"].lower() in blob)]
    if leaks:
        raise SystemExit(f"GRADER LEAK BLOCKED: feedback would reveal {leaks[:5]}")
    json.dump(out, open(f"{run}/private/grade.json", "w"), indent=1)
    json.dump(fb, open(f"{run}/feedback.json", "w"), indent=1)
    return out, fb


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("run"); ap.add_argument("--variant-json", required=True)
    a = ap.parse_args()
    o, _ = grade(a.run, json.loads(a.variant_json))
    print(json.dumps(o["summary"]))
