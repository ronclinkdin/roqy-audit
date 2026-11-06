"""One permissions edit should close two CI chains, and the patch must apply."""
import os, shutil, subprocess, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from roqy_audit.cli import main, scan_path
from roqy_audit.report import to_markdown

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "remediate-ci")
CLIENT = os.path.join(ROOT, "lab", "vuln-lab", "client-repo")
CLEAN = os.path.join(ROOT, "lab", "harness-loop", "variants", "clean-repo")


def test_permissions_block_breaks_two_ci_chains(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    payload = scan_path(str(repo), use_adapters=False)
    fixes = payload["remediation"]
    assert fixes and len(fixes) <= 3
    top = fixes[0]
    assert top["id"] == "permissions-block"
    assert top["p0_chains"] == 2
    assert {c["scope"] for c in top["chains"]} == {"ci.yml", "release.yml"}
    assert all(c["id"] == "ci-cloud-takeover" for c in top["chains"])
    assert "contents: read" in top["why"] or "contents: read" in "".join(p["diff"] for p in top["patches"])
    assert len(top["patches"]) == 2
    blob = "\n".join(p["diff"] for p in top["patches"])
    assert "AKIA" not in blob and "ghp_" not in blob
    for patch in top["patches"]:
        proc = subprocess.run(["patch", "-p1"], input=patch["diff"], text=True, cwd=repo, capture_output=True)
        assert proc.returncode == 0, proc.stderr
    after = scan_path(str(repo), use_adapters=False)
    assert not any(c["id"] == "ci-cloud-takeover" for c in after["chains"])
    md = to_markdown(payload)
    assert "## How to break these chains" in md
    assert "permissions-block" not in md or "least-privilege" in md
    only = tmp_path / "fixes.md"
    assert main(["scan", str(repo), "--no-adapters", "--fail-on", "none", "--remediate", str(only)]) == 0
    text = only.read_text()
    assert text.startswith("## How to break these chains")
    assert "Attack chains" not in text


def test_clean_repo_has_no_remediation_and_client_report_has_the_section():
    clean = scan_path(CLEAN, use_adapters=False)
    assert clean["findings"] == [] and clean["remediation"] == []
    client = scan_path(CLIENT, use_adapters=False)
    md = to_markdown(client)
    assert "## How to break these chains" in md
    assert len(client["remediation"]) <= 3
