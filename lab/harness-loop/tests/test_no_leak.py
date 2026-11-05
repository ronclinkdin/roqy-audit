import json, os, subprocess, sys
H = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED = os.path.join(os.path.dirname(H), "vuln-lab", "EXPECTED-FINDINGS.yaml")
def test_proposer_cannot_open_grader(tmp_path):
    fb = tmp_path / "fb.json"; fb.write_text(json.dumps({"misses": []}))
    code = ("import runpy,sys;sys.argv=['p'];"
            "exec(open('%s/proposer/propose.py').read().split('import yaml')[0]);"
            "open('%s')") % (H, EXPECTED)
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert p.returncode != 0 and "grader is hidden" in p.stderr
def test_proposer_runs_on_feedback(tmp_path):
    fb = tmp_path / "fb.json"
    fb.write_text(json.dumps({"severity_mismatch": [{"token": "m-x", "check_id": "W7", "got": "P1"}], "clean_fp_by_check": {"NEW-CICD-PR-APPLY": 1}}))
    import shutil
    sd = tmp_path / "surface"; shutil.copytree(f"{H}/surface", sd)
    (sd / "checks-overlay.yaml").write_text("version: 0\nchecks: {}\nparams: {}\n")
    p = subprocess.run([sys.executable, f"{H}/proposer/propose.py", str(fb), str(sd)], capture_output=True, text=True)
    edits = json.loads(p.stdout)
    assert any(e.get("param") == "NEW-CICD-PR-APPLY.scope" and e["value"] == "job" for e in edits)
    assert any(e["kind"] == "set_severity" and e["value"] == "P2" for e in edits)
