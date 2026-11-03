#!/usr/bin/env python3
"""Scenario runner: one live harness run per audit target.

Scenarios:
  repo  — infra-readiness-audit on /root/roqy (static, no live cloud)
  vps   — live-infra-audit on this VPS (docker/ss/df, read-only)
  gcp   — live-infra-audit on GCP canary project roqy-512012
  gke   — live-infra-audit on a throwaway GKE cluster (creates + deletes, costs ~$0.10)

Usage: python3 run_scenarios.py repo vps gcp [gke]
Each scenario: run hermes chat with the skill, then validate artifacts.
"""
import datetime
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from run_audit_harness import validate  # noqa: E402

ROOT = Path.home() / "infra-readiness-audit"
GCLOUD = "/tmp/google-cloud-sdk/bin/gcloud"
VERDICT_RULE = (
    "Every finding heading must carry exactly one verdict: CONFIRMED, NEEDS_VALIDATION, "
    "or REJECTED. No other verdict words. Sections you cannot run get a not_applicable "
    "line with the reason."
)

SCENARIOS = {
    "repo": {
        "skill": "infra-readiness-audit",
        "prompt": (
            "Run the infra-readiness-audit skill in full audit mode on the repository /root/roqy. "
            "Static repo review only, no live cloud commands. "
            f"Write REPORT.md and findings.json to {ROOT}/roqy-harness/<today>/. {VERDICT_RULE}"
        ),
        "out": ROOT / "roqy-harness",
        "report_names": ("REPORT.md", "live.md"),
    },
    "vps": {
        "skill": "live-infra-audit",
        "prompt": (
            "Run the live-infra-audit skill in full audit mode on THIS VPS (localhost, docker host). "
            "Read-only: docker ps/inspect, ss, df, crontab -l, ufw status. No changes, no restarts. "
            f"Write live.md to {ROOT}/vps-harness/<today>/. {VERDICT_RULE}"
        ),
        "out": ROOT / "vps-harness",
        "report_names": ("live.md", "REPORT.md"),
    },
    "gcp": {
        "skill": "live-infra-audit",
        "prompt": (
            "Run the live-infra-audit skill in full audit mode against GCP project roqy-512012 "
            f"(read-only, gcloud at {GCLOUD}, terraform at /tmp/terraform, billing account 013EAB-A843BD-B58B60). "
            f"Write live.md to {ROOT}/gcp-harness/<today>/. Do not change any resource. "
            "This is a canary project with planted findings; detect them. " + VERDICT_RULE
        ),
        "out": ROOT / "gcp-harness",
        "report_names": ("live.md", "REPORT.md"),
    },
    "gke": {
        "skill": "live-infra-audit",
        "prompt": (
            "GKE canary validation. Create a throwaway zonal GKE cluster audit-harness-gke in "
            "us-west1-b (1 node e2-small), plant nothing, audit the DEFAULT state with the "
            "live-infra-audit skill K7-K13 checks (kubectl is at /tmp/google-cloud-sdk/bin/kubectl), "
            "then DELETE the cluster immediately. Read-only against workloads; cluster create/delete "
            "is the only allowed mutation. "
            f"Write live.md to {ROOT}/gke-harness/<today>/. {VERDICT_RULE}"
        ),
        "out": ROOT / "gke-harness",
        "report_names": ("live.md", "REPORT.md"),
    },
}


def run_scenario(name: str) -> bool:
    sc = SCENARIOS[name]
    today = datetime.date.today().isoformat()
    out_dir = sc["out"] / today
    cmd = [
        "hermes", "chat", "-q", sc["prompt"],
        "-s", sc["skill"], "--yolo", "--max-turns", "12",
    ]
    print(f"=== SCENARIO {name} ===")
    print("RUN:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    print("hermes exit:", r.returncode)
    report = None
    for rn in sc["report_names"]:
        p = out_dir / rn
        if p.exists():
            report = p
            break
    if not report:
        print("FAIL  no report produced in", out_dir)
        return False
    print("validating:", report)
    return validate(report.parent)


if __name__ == "__main__":
    names = sys.argv[1:] or ["repo", "vps", "gcp"]
    results = {}
    for n in names:
        try:
            results[n] = run_scenario(n)
        except Exception as e:
            print(f"FAIL  {n}: {e}")
            results[n] = False
    print("\n=== SUMMARY ===")
    for n, ok in results.items():
        print(f"{n}: {'GREEN' if ok else 'RED'}")
    sys.exit(0 if all(results.values()) else 1)
