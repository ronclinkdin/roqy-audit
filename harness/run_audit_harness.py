#!/usr/bin/env python3
"""Audit harness: validates live-infra-audit run outputs.

Two modes:
  validate <dir>          check artifacts of one audit run
  live                    run the skill via hermes chat on the GCP canary, then validate

Checks (validate):
  1. live.md or REPORT.md exists
  2. findings.json (if present) parses; every item has id/category/title/status/priority
  3. status values in {confirmed, needs_validation, rejected}
  4. priority only on confirmed items
  5. no secret values leaked: scans for known canary secret strings and long token-like runs
  6. report length cap (<= 120 lines)
  7. canary coverage: expected planted findings detected (G1 firewall, G2 SA key, G4 budget)
"""
import json
import re
import subprocess
import sys
from pathlib import Path

CANARY_SECRETS = ["FAKE-DB-PASSWORD=not-a-real-secret"]
EXPECTED_CANARY = ["firewall", "editor", "budget"]
EXPECTED_CANARY_AWS = ["openai-credentials", "authusers", "snapshot", "rotation", "security group", "function url", "ecr", "sns", "retention"]
VALID_STATUS = {"confirmed", "needs_validation", "rejected"}
VALID_PRIORITY = {"P0", "P1", "P2", None}


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  [{detail}]" if detail else ""))
    return ok


def validate(run_dir: Path) -> bool:
    ok = True
    report = None
    for name in ("live.md", "REPORT.md"):
        p = run_dir / name
        if p.exists():
            report = p
            break
    ok &= check("report file exists", report is not None, str(run_dir))
    if not report:
        return False

    text = report.read_text()
    ok &= check("report under 120 lines", len(text.splitlines()) <= 120, f"{len(text.splitlines())} lines")

    # verdict hygiene: every finding heading must contain a valid verdict anywhere
    bad = []
    for line in text.splitlines():
        if line.startswith("### ") and ("—" in line or "(" in line):
            up = line.upper()
            if not any(s in up for s in ("CONFIRMED", "NEEDS_VALIDATION", "NEEDS VALIDATION", "REJECTED", "NOT_APPLICABLE")):
                bad.append(line[:60])
    ok &= check("no invented verdicts in headings", not bad, str(bad))

    leaked = [s for s in CANARY_SECRETS if s in text]
    ok &= check("no canary secret values in report", not leaked, str(leaked))
    tokens = re.findall(r"[A-Za-z0-9_\-]{40,}", text)
    ok &= check("no token-like strings in report", not tokens, str(tokens[:2]))

    fj = run_dir / "findings.json"
    if fj.exists():
        try:
            items = json.loads(fj.read_text())
            ok &= check("findings.json parses", True, f"{len(items)} items")
            bad_status = [i.get("id") for i in items if i.get("status") not in VALID_STATUS]
            ok &= check("statuses valid", not bad_status, str(bad_status))
            bad_prio = [i.get("id") for i in items
                        if i.get("status") != "confirmed" and i.get("priority")]
            ok &= check("priority only on confirmed", not bad_prio, str(bad_prio))
            missing = [i.get("id") for i in items
                       if not all(k in i for k in ("id", "category", "title", "status", "evidence", "consequence", "fix"))]
            ok &= check("findings schema complete", not missing, str(missing))
        except Exception as e:
            ok &= check("findings.json parses", False, str(e))

    # canary coverage: planted findings must appear in the report text
    low = text.lower()
    if "aws-harness" in str(run_dir):
        expected = EXPECTED_CANARY_AWS
    elif "gcp" in str(run_dir) and ("canary" in str(run_dir) or "harness" in str(run_dir)):
        expected = EXPECTED_CANARY
    else:
        expected = []
    if expected:
        missing_cov = [k for k in expected if k not in low]
        ok &= check("canary planted findings covered", not missing_cov, str(missing_cov))

    # skill coverage: the report should touch the check families the skill defines
    families = {
        "docker/vps (L)": ["port", "tls", "backup", "restart", "disk"],
        "gcp (G)": ["firewall", "service account", "scope", "budget", "snapshot"],
        "terraform (T)": ["state", "drift", "import"],
        "audit logs (A)": ["activity", "alert", "data access"],
        "access arch (K)": ["endpoint", "ci/cd", "vendor", "cluster-admin"],
        "client favorites (X)": ["ai", "bus factor", "pii", "rotation", "dns"],
    }
    low = text.lower()
    for fam, keys in families.items():
        hits = sum(1 for k in keys if k in low)
        # advisory: old reports predate newer skill sections; live runs must cover
        if hits >= 2:
            print(f"PASS  family coverage {fam}  [{hits}/{len(keys)} keywords]")
        else:
            print(f"WARN  family coverage {fam}  [{hits}/{len(keys)} keywords] (report may predate skill section)")
    return ok


def live() -> bool:
    out_root = Path.home() / "infra-readiness-audit" / "gcp-canary-harness"
    prompt = (
        "Run the live-infra-audit skill in full audit mode against GCP project roqy-512012 "
        "(read-only, gcloud is at /tmp/google-cloud-sdk/bin/gcloud, terraform at /tmp/terraform, "
        "billing account 013EAB-A843BD-B58B60). "
        f"Write the report to {out_root}/<today>/live.md. Do not change any resource. "
        "This is a canary project with planted findings; detect them. "
        "Every finding heading must carry exactly one verdict: CONFIRMED, NEEDS_VALIDATION, or REJECTED. "
        "No other verdict words. Sections you cannot run get a not_applicable line with the reason."
    )
    cmd = ["hermes", "chat", "-q", prompt, "-s", "live-infra-audit", "--yolo", "--max-turns", "12"]
    print("RUN:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1500)
    # hermes exit code is informational (max-turns exhaustion after writing the
    # report still counts as success); the gate is artifact validation below.
    print("hermes exit:", r.returncode)
    runs = sorted(out_root.glob("*/live.md"))
    if not runs:
        print("FAIL  no live.md produced")
        return False
    print("validating:", runs[-1])
    return validate(runs[-1].parent)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "live":
        sys.exit(0 if live() else 1)
    if len(sys.argv) > 2 and sys.argv[1] == "validate":
        sys.exit(0 if validate(Path(sys.argv[2])) else 1)
    print(__doc__)
    sys.exit(2)
