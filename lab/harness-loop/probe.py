#!/usr/bin/env python3
"""PROBE: run the audit executors for one variant with a given surface, collect findings + scale metrics, call the hidden grader.
Usage: probe.py --surface surface/ --run runs/<id>/<name> [--mode live|replay --cache <raw dir>] [--variants full,clean-repo]"""
import argparse, json, os, shutil, subprocess, sys, time, yaml
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
CFG = yaml.safe_load(open(os.path.join(HERE, "config.yaml")))


def _repo_path(p):
    if not p or os.path.isabs(p):
        return p
    return os.path.join(REPO, p)


CFG["lab_run"] = _repo_path(CFG["lab_run"])
for _variant in CFG["variants"].values():
    for _key in ("repo", "redacted_state", "envelope_static"):
        if _variant.get(_key):
            _variant[_key] = _repo_path(_variant[_key])
LAB = CFG["lab_run"]


def sh(cmd, env, log):
    t = time.time()
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, cwd=LAB)
    open(log, "a").write(f"$ {' '.join(cmd)}\n{p.stdout}\n{p.stderr}\n")
    return p, time.time() - t


def regions_for(v):
    r = v.get("regions", CFG["regions"])
    if r == "all":
        # list of enabled regions via the read-only role (guarded)
        sys.path.insert(0, LAB); from awsrun import aws
        _, d, _ = aws("REGIONS", ["ec2", "describe-regions"], "eu-central-1")
        r = [x["RegionName"] for x in (d or {}).get("Regions", [])]
    return r


def probe(surface, run, mode="live", cache=None, variants=None):
    run, surface = os.path.abspath(run), os.path.abspath(surface)
    cache = os.path.abspath(cache) if cache else None
    os.makedirs(run, exist_ok=True)
    shutil.copytree(surface, f"{run}/surface", dirs_exist_ok=True)
    base = {k: v for k, v in os.environ.items() if k not in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")}
    base.update(ROQY_OVERLAY=f"{run}/surface/checks-overlay.yaml", ROQY_GUARDRAILS=f"{run}/surface/guardrails.yaml")
    names = variants or [n for n, v in CFG["variants"].items() if v.get("enabled")]
    results = {}
    for name in names:
        v = CFG["variants"][name]; vr = f"{run}/{name}"; os.makedirs(vr, exist_ok=True)
        m = {"variant": name, "mode": mode, "stages": {}, "guard_violations": 0, "permission_gaps": []}
        T = time.time(); findings = []
        env = dict(base, AUDIT_PROFILE=v.get("profile", "roqy-audit-ro"))
        if v.get("core"):
            regs = regions_for(v); m["regions"] = len(regs)
            e = dict(env, REGIONS=",".join(regs), AUDIT_RAW_DIR=f"{vr}/raw-core", AUDIT_CMD_LOG=f"{vr}/core-commands.jsonl",
                     AUDIT_FINDINGS_OUT=f"{vr}/core.json")
            if mode == "replay" and cache: e["AUDIT_REPLAY_DIR"] = cache
            p, dt = sh([sys.executable, "audit_v3.py"], e, f"{vr}/probe.log")
            m["stages"]["core_s"] = round(dt, 1)
            if "GuardViolation" in p.stderr: m["guard_violations"] += 1
            if p.returncode == 0:
                d = json.load(open(f"{vr}/core.json")); findings += d["findings"]; m["permission_gaps"] += [list(g) for g in d["permission_gaps"]]
                cl = [json.loads(x) for x in open(f"{vr}/core-commands.jsonl")]
                m["api_calls_live"] = sum(1 for x in cl if x.get("src") == "live"); m["api_calls_replay"] = sum(1 for x in cl if x.get("src") == "replay")
            else:
                m["core_error"] = p.stderr[-600:]
        if v.get("envelope"):
            e = dict(env, ENVELOPE_OUT=f"{vr}/envelope")
            p, dt = sh([sys.executable, "audit_envelope.py", "--repo", v["repo"], "--redacted-state", v["redacted_state"]], e, f"{vr}/probe.log")
            m["stages"]["envelope_s"] = round(dt, 1)
            if "GuardViolation" in p.stderr: m["guard_violations"] += 1
            if p.returncode == 0:
                d = json.load(open(f"{vr}/envelope/findings-envelope.json")); findings += d["findings"]; m["permission_gaps"] += [list(g) for g in d["permission_gaps"]]
                c = json.load(open(f"{vr}/envelope/commands-envelope.json"))
                m["api_calls_live"] = m.get("api_calls_live", 0) + sum(1 for x in c if x["kind"] == "aws")
                m["k8s_calls"] = sum(1 for x in c if x["kind"] != "aws")
            else:
                m["envelope_error"] = p.stderr[-600:]
        if v.get("envelope_static"):
            e = dict(env, ENVELOPE_OUT=f"{vr}/envelope")
            p, dt = sh([sys.executable, "audit_envelope.py", "--repo", v["envelope_static"], "--static-only"], e, f"{vr}/probe.log")
            m["stages"]["envelope_static_s"] = round(dt, 1)
            if p.returncode == 0: findings += json.load(open(f"{vr}/envelope/findings-envelope.json"))["findings"]
        m["wall_s"] = round(time.time() - T, 1)
        if any(k.endswith("_error") for k in m) and m["guard_violations"] == 0:
            json.dump(m, open(f"{vr}/metrics.json", "w"), indent=1)
            raise SystemExit(f"executor crashed in variant {name}, see {vr}/metrics.json")
        json.dump({"findings": findings}, open(f"{vr}/findings-merged.json", "w"), indent=1, default=str)
        json.dump(m, open(f"{vr}/metrics.json", "w"), indent=1)
        results[name] = (vr, m, findings)
    # grade: lab variants score against the hidden truth; clean variants contribute FP counts to the full run
    gr = os.path.join(HERE, "grader", "grade.py")
    full = results.get("full")
    if full:
        clean = [n for n in results if n.startswith("clean")]
        for n in clean:
            shutil.copy(f"{results[n][0]}/findings-merged.json", f"{full[0]}/{n}.json")
        vj = json.dumps({"name": "full", "score": CFG["variants"]["full"]["score"], "clean_parts": clean})
        p = subprocess.run([sys.executable, gr, full[0], "--variant-json", vj], capture_output=True, text=True)
        if p.returncode != 0: raise SystemExit(p.stderr + p.stdout)
        summary = json.loads(p.stdout.strip().splitlines()[-1])
        # merge scale metrics of all variants into the proposer-visible feedback
        fb = json.load(open(f"{full[0]}/feedback.json"))
        fb["scale"] = {n: {k: r[1].get(k) for k in ("wall_s", "stages", "api_calls_live", "api_calls_replay", "k8s_calls", "regions")} for n, r in results.items()}
        json.dump(fb, open(f"{full[0]}/feedback.json", "w"), indent=1)
        json.dump({"summary": summary, "feedback": f"{full[0]}/feedback.json", "scale": fb["scale"]}, open(f"{run}/probe-result.json", "w"), indent=1)
        return summary, f"{full[0]}/feedback.json", fb["scale"]
    return None, None, {n: r[1] for n, r in results.items()}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--surface", default=os.path.join(HERE, "surface")); ap.add_argument("--run", required=True)
    ap.add_argument("--mode", default="live"); ap.add_argument("--cache"); ap.add_argument("--variants")
    a = ap.parse_args()
    s, fbp, sc = probe(a.surface, a.run, a.mode, a.cache, a.variants.split(",") if a.variants else None)
    print(json.dumps({"summary": s, "scale": sc}, indent=1))
