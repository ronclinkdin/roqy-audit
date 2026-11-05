"""Pluggable LLM proposer (no Vertex AI). The model sees EXACTLY what the heuristic proposer sees:
sanitized feedback + current surface. It returns edits in the same schema; loop.compose validates them
(catalogued knobs only, guardrails may only tighten) and the probe decides.

provider: none     -> stub, returns []
provider: command  -> runs cfg["command"] (e.g. a local Ollama/OpenAI/Claude script), JSON on stdin, JSON list on stdout
"""
import json, shlex, subprocess

SYSTEM = ("You improve a read-only AWS/K8s/IaC audit. You get aggregate per-category scores, opaque miss tokens mapped to check ids, "
          "severity mismatches (emitted value only), false-positive counts per check, permission gaps and scale numbers. "
          "Propose at most 8 edits as a JSON list using kinds set_severity/set_param/set_disabled/append_prompt/decision. "
          "Never propose reading secret values or widening permissions; those are decisions for a human.")


def propose(feedback, surface, cfg):
    if (cfg or {}).get("provider", "none") == "none" or not cfg.get("command"):
        return []
    payload = json.dumps({"system": SYSTEM, "feedback": feedback, "surface": surface})
    p = subprocess.run(shlex.split(cfg["command"]), input=payload, capture_output=True, text=True, timeout=cfg.get("timeout", 300))
    try:
        edits = json.loads(p.stdout)
        return [e for e in edits if isinstance(e, dict) and e.get("kind")][:8]
    except Exception:
        return []
