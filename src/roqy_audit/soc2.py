"""Indicative SOC 2 Common Criteria labels for check ids. Not an auditor opinion."""
import os

import yaml

_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "soc2.yaml")
_DOC = yaml.safe_load(open(_PATH, encoding="utf-8"))
CHECKS = _DOC["checks"]
DEFAULT = list(_DOC.get("default") or ["CC6.1"])
CRITERIA = _DOC.get("criteria") or {}
DISCLAIMER = "Indicative mapping to SOC 2 Common Criteria, not an auditor opinion."


def for_check(check_id, tool="roqy"):
    if check_id in CHECKS:
        return list(CHECKS[check_id])
    bare = check_id.split(":", 1)[0]
    if bare in CHECKS:
        return list(CHECKS[bare])
    if tool in CHECKS:
        return list(CHECKS[tool])
    return list(DEFAULT)
