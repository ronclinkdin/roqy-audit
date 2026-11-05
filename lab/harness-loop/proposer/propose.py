#!/usr/bin/env python3
"""PROPOSE: candidate edits to the editable surface, from the SANITIZED feedback only.
The grader is hidden: an audit hook blocks this process from opening EXPECTED-FINDINGS, the grader dir,
or any run's private/ dir. Input: feedback.json + surface dir. Output: JSON list of edits on stdout.

Edit kinds (validated by loop.compose before use):
  set_severity  {check_id, value: P0..P3}
  set_param     {param, value}            value must come from surface/knob-catalog.yaml
  set_disabled  {check_id, value: bool}
  append_prompt {text}                    recorded, scored only when an LLM executor runs the agent
  decision      {text}                    needs a human (e.g. IAM permission change) - never auto-applied
"""
import json, os, sys

FORBIDDEN = ("EXPECTED-FINDINGS", f"{os.sep}grader", f"{os.sep}private{os.sep}", "known-unplanted", ".salt")


def _hook(event, args):
    if event == "open" and args and isinstance(args[0], (str, bytes, os.PathLike)):
        p = os.fsdecode(args[0])
        if any(x in p for x in FORBIDDEN):
            raise PermissionError(f"proposer may not read {p} (grader is hidden)")


sys.addaudithook(_hook)
import yaml  # noqa: E402  (after the hook, so even yaml's own opens are covered)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import llm_hook  # noqa: E402

SEVS = ["P0", "P1", "P2", "P3"]


def heuristics(fb, overlay, catalog):
    out = []
    checks = overlay.get("checks") or {}
    params = overlay.get("params") or {}

    def knobs_for(cid):
        return [k for k in catalog if k == cid or k.startswith(cid + ".")]

    # 1. severity mismatch: the check fired on the right resource but at a severity the grader disagrees with.
    #    The proposer does NOT know the expected value -> propose every other level, the probe picks.
    for sm in fb.get("severity_mismatch", []):
        for s in SEVS:
            if s != sm["got"]:
                out.append({"kind": "set_severity", "check_id": sm["check_id"], "value": s,
                            "why": f"severity mismatch on {sm['check_id']} (emitted {sm['got']}), try {s}"})
    # 2. false positives on clean variants: try every catalogued knob of that check (tightening), never disable first.
    for cid, n in fb.get("clean_fp_by_check", {}).items():
        for k in knobs_for(cid):
            for alt in catalog[k]["alternatives"]:
                if params.get(k) != alt:
                    out.append({"kind": "set_param", "param": k, "value": alt, "why": f"{n} clean-variant FP on {cid}: try knob {k}={alt!r}"})
        if not knobs_for(cid):
            out.append({"kind": "decision", "text": f"{cid}: {n} false positive(s) on a clean variant and no tunable knob -> needs a code change in the check"})
    # 3. misses: re-enable a disabled check, widen its knobs; a permission gap on that check is a human decision.
    gaps = {}
    for g in fb.get("permission_gaps", []):
        gaps.setdefault(g[0], set()).add(g[1])
    for ms in fb.get("misses", []):
        for cid in ms["check_ids"]:
            if (checks.get(cid) or {}).get("disabled"):
                out.append({"kind": "set_disabled", "check_id": cid, "value": False, "why": f"miss {ms['token']} expects {cid}, which is disabled"})
            for k in knobs_for(cid):
                for alt in catalog[k]["alternatives"]:
                    if params.get(k) != alt:
                        out.append({"kind": "set_param", "param": k, "value": alt, "why": f"miss {ms['token']} ({ms['category']}) on {cid}: widen {k}"})
            if cid in gaps:
                out.append({"kind": "decision", "text": f"{cid}: audit role lacks {sorted(gaps[cid])} -> add to the read-only role (human approval)"})
            out.append({"kind": "append_prompt", "text": f"- {cid}: if the API answers 'not enabled'/'no resources', that absence is the finding; AccessDenied is a permission gap, not a pass."})
    # 4. untriaged unmatched findings (possible FP on the lab): tighten knobs of that check.
    for cid, n in fb.get("untriaged_unmatched_by_check", {}).items():
        for k in knobs_for(cid):
            for alt in [catalog[k]["default"]] + catalog[k]["alternatives"]:
                if params.get(k, catalog[k]["default"]) != alt:
                    out.append({"kind": "set_param", "param": k, "value": alt, "why": f"{n} untriaged unmatched on {cid}: try {k}={alt!r}"})
    # de-duplicate
    seen, uniq = set(), []
    for e in out:
        key = json.dumps({k: v for k, v in e.items() if k != "why"}, sort_keys=True)
        if key not in seen:
            seen.add(key); uniq.append(e)
    return uniq


def main():
    fb = json.load(open(sys.argv[1]))
    surface = sys.argv[2]
    cfg_llm = json.loads(sys.argv[3]) if len(sys.argv) > 3 else {"provider": "none"}
    overlay = yaml.safe_load(open(os.path.join(surface, "checks-overlay.yaml"))) or {}
    catalog = yaml.safe_load(open(os.path.join(surface, "knob-catalog.yaml"))) or {}
    prompt = open(os.path.join(surface, "prompt.md")).read()
    edits = [dict(e, source="heuristic") for e in heuristics(fb, overlay, catalog)]
    edits += [dict(e, source="llm") for e in llm_hook.propose(fb, {"overlay": overlay, "knob_catalog": catalog, "prompt": prompt}, cfg_llm)]
    print(json.dumps(edits, indent=1))


if __name__ == "__main__":
    main()
