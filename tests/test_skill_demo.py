"""Ratings for the five synthetic check-skill fixtures. No network."""
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from roqy_audit.skill_risk import assess

DEMO = os.path.join(os.path.dirname(__file__), "fixtures", "skill-demo")


def _ids(r, sev=None):
    return {f["id"] for f in r["findings"] if sev is None or f["severity"] == sev}


def test_malicious_a_hidden_exfil_is_high():
    r = assess(os.path.join(DEMO, "malicious-a"), "malicious-a")
    assert r["security_topic"] is False
    assert {"SR-EXFIL-INSTR", "SR-HIDDEN-COMMENT", "SR-SECRET-PATHS"} <= _ids(r)
    assert r["risk"] == "high"


def test_malicious_b_install_hook_stays_high():
    r = assess(os.path.join(DEMO, "malicious-b"), "malicious-b")
    assert "SR-INSTALL-HOOK" in _ids(r, "high")
    assert "SR-PIPE-SHELL" in _ids(r)
    assert r["risk"] == "high"


def test_malicious_c_mcp_latest_root_and_secret_are_high():
    for kind in ("auto", "mcp"):
        r = assess(os.path.join(DEMO, "malicious-c"), "malicious-c", kind=kind)
        ids = _ids(r)
        assert "SR-MCP-SECRET-LITERAL" in ids
        assert "SR-UNPINNED-INSTALL" in ids
        assert "SR-MCP-BROAD-FS" in _ids(r, "high")
        assert r["risk"] == "high"


def test_benign_formatter_stays_low():
    r = assess(os.path.join(DEMO, "benign-a"), "benign-a")
    assert r["risk"] == "low"
    assert not _ids(r, "high") and not _ids(r, "medium")


def test_benign_security_skill_prose_is_low():
    r = assess(os.path.join(DEMO, "benign-b"), "benign-b")
    assert r["security_topic"] is True
    assert r["risk"] == "low"
    assert not _ids(r, "high") and not _ids(r, "medium")
