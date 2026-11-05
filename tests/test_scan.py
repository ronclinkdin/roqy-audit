"""Chains, SOC 2 labels, adapter normalization, SARIF, and CLI exit codes. No network."""
import json, os, sys

import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from roqy_audit import adapters, chains, cli, report, soc2
from roqy_audit.repo_scan import scan_static

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CLIENT = os.path.join(ROOT, "lab", "vuln-lab", "client-repo")
CLEAN = os.path.join(ROOT, "lab", "harness-loop", "variants", "clean-repo")


def _ours(**kw):
    base = {"check_id": "X", "resource": "r", "title": "t", "severity": "P2", "status": "confirmed", "evidence": "f", "layer": "iac", "tool": "roqy"}
    base.update(kw)
    return base


def test_chain_rules_are_explicit():
    findings = [
        _ours(check_id="NEW-CICD-ACTION-PIN", severity="P2"),
        _ours(check_id="NEW-CICD-PERMS", severity="P2"),
        _ours(check_id="NEW-CICD-NO-OIDC", severity="P1"),
        _ours(check_id="NEW-DOCKER-PIPE-SHELL", severity="P1"),
        _ours(check_id="NEW-DOCKER-FROM-PIN", severity="P2"),
        _ours(check_id="NEW-AGENT-MCP-PIN", severity="P1"),
        _ours(check_id="NEW-AGENT-MCP-FS", severity="P2"),
        _ours(check_id="NEW-TF-HARDCODED-SECRET", severity="P1"),
    ]
    got = {c["id"]: c for c in chains.build_chains(findings)}
    assert set(got) == {"ci-cloud-takeover", "build-time-code-injection", "agent-tool-compromise", "secret-direct-access"}
    takeover = got["ci-cloud-takeover"]
    assert takeover["severity"] == "P0"
    assert [s["check_id"] for s in takeover["steps"]][:3] == ["NEW-CICD-ACTION-PIN", "NEW-CICD-PERMS", "NEW-CICD-NO-OIDC"]
    assert takeover["fix_order"]
    # one leg missing -> chain does not fire
    assert "ci-cloud-takeover" not in {c["id"] for c in chains.build_chains(findings[:1])}


def test_soc2_map_covers_static_checks_and_is_labeled():
    text = open(os.path.join(ROOT, "src", "roqy_audit", "repo_scan.py"), encoding="utf-8").read()
    ids = set()
    for line in text.splitlines():
        if 'find("NEW-' in line:
            ids.add(line.split('find("', 1)[1].split('"', 1)[0])
    missing = ids - set(soc2.CHECKS)
    assert not missing, missing
    assert soc2.for_check("NEW-CICD-PR-APPLY") == ["CC6.1", "CC8.1"]
    assert "CC6.7" in soc2.for_check("NEW-TF-STATE-SECRETS")
    assert soc2.for_check("gitleaks:aws-access-token", tool="gitleaks") == ["CC6.1", "CC6.7"]
    assert "not an auditor opinion" in soc2.DISCLAIMER
    doc = yaml.safe_load(open(os.path.join(ROOT, "src", "roqy_audit", "soc2.yaml"), encoding="utf-8"))
    assert "CC9.2" in doc["criteria"]


def test_adapters_missing_and_mocked(monkeypatch, tmp_path):
    monkeypatch.setattr(adapters, "_which", lambda name: None)
    findings, rows = adapters.run_adapters(str(tmp_path))
    assert findings == []
    assert {r["name"] for r in rows} == set(adapters.TOOLS)
    assert all(r["status"] == "not run" for r in rows)

    def which(name):
        return "/usr/bin/gitleaks" if name == "gitleaks" else ("/usr/bin/trivy" if name == "trivy" else None)

    def fake_run(cmd, timeout=90):
        class P:
            returncode = 0
            stdout = ""
            stderr = ""
        if cmd[0] == "gitleaks":
            report = cmd[cmd.index("--report-path") + 1]
            open(report, "w").write(json.dumps([{"RuleID": "aws-access-token", "File": "infra/variables.tf"}]))
        if cmd[0] == "trivy":
            P.stdout = json.dumps({"Results": [{"Target": "Dockerfile", "Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "PkgName": "openssl", "Severity": "HIGH", "Title": "openssl"}]}]})
        return P()

    monkeypatch.setattr(adapters, "_which", which)
    monkeypatch.setattr(adapters, "_run", fake_run)
    findings, rows = adapters.run_adapters(str(tmp_path))
    assert any(f["check_id"] == "gitleaks:aws-access-token" for f in findings)
    assert any(f["check_id"] == "trivy:CVE-2024-0001" and f["severity"] == "P1" for f in findings)
    assert all(r["status"] == "not run" for r in rows if r["name"] not in ("gitleaks", "trivy"))
    ours = [_ours(check_id="NEW-TF-HARDCODED-SECRET", evidence="infra/variables.tf", title="hardcoded secret default")]
    kept = adapters.dedupe(ours, [f for f in findings if f["tool"] == "gitleaks"])
    assert kept == []
    # a tool that raises is reported, not fatal
    def boom(*_a, **_k):
        raise RuntimeError("boom")

    monkeypatch.setattr(adapters, "_which", lambda name: "/usr/bin/checkov" if name == "checkov" else None)
    monkeypatch.setattr(adapters, "_run", boom)
    findings, rows = adapters.run_adapters(str(tmp_path))
    assert findings == []
    assert next(r for r in rows if r["name"] == "checkov")["status"] == "not run"


def test_sarif_and_markdown_and_exit(tmp_path):
    payload = cli.scan_path(CLIENT, use_adapters=False)
    assert any(c["id"] == "ci-cloud-takeover" for c in payload["chains"])
    assert any(f["check_id"] == "NEW-AGENT-MCP-PIN" for f in payload["findings"])
    sarif = json.loads(report.to_sarif(payload))
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "roqy-audit"
    assert run["results"]
    assert run["results"][0]["ruleId"]
    assert run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    md = report.to_markdown(payload)
    assert "Attack chains" in md and "CI to cloud takeover" in md and "not an auditor opinion" in md
    assert "Tools run / not run" in md
    clean = cli.scan_path(CLEAN, use_adapters=False)
    assert clean["findings"] == [] and clean["chains"] == []
    assert cli.main(["scan", CLIENT, "--no-adapters", "--fail-on", "none"]) == 0
    assert cli.main(["scan", CLIENT, "--no-adapters", "--fail-on", "P0", "--md", str(tmp_path / "r.md")]) == 1
    assert cli.main(["scan", CLEAN, "--no-adapters", "--fail-on", "P0"]) == 0


def test_static_module_is_what_the_lab_imports():
    text = open(os.path.join(ROOT, "lab", "lab-run", "audit_envelope.py"), encoding="utf-8").read()
    assert "from roqy_audit.repo_scan import scan_static" in text
    got = []
    scan_static(CLIENT, lambda *a, **k: got.append(a[0]), __import__("re").compile("secret"))
    assert "NEW-DOCKER-PIPE-SHELL" in got and "NEW-CICD-PR-APPLY" in got
