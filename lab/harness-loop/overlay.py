"""Runtime view of the editable surface (surface/checks-overlay.yaml) for the audit scripts.
The audit code stays the executor; the overlay is what the improvement loop may edit:
  checks.<ID>.severity  -> override the severity a check emits (needs_validation findings keep None)
  checks.<ID>.disabled  -> drop the check's findings
  params.<name>         -> tunable knobs (regexes, port lists, thresholds) read by the checks
"""
import os
try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None
PATH = os.environ.get("ROQY_OVERLAY", os.path.join(os.path.dirname(os.path.abspath(__file__)), "surface", "checks-overlay.yaml"))
D = (yaml.safe_load(open(PATH)) or {}) if (yaml and PATH and os.path.exists(PATH)) else {}
CHECKS = D.get("checks") or {}
PARAMS = D.get("params") or {}


def param(name, default):
    return PARAMS.get(name, default)


def apply(f):
    c = CHECKS.get(f.get("check_id")) or {}
    if c.get("disabled"):
        return None
    if c.get("severity") and f.get("severity") is not None:
        f["severity"] = c["severity"]
        f["severity_source"] = "overlay"
    return f
