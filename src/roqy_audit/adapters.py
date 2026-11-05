"""Optional third-party scanners. Missing tools are 'not run'. A tool error never fails the scan."""
import json, os, re, shutil, subprocess, tempfile

from roqy_audit.paths import noise_path

TOOLS = ("trivy", "gitleaks", "zizmor", "checkov", "osv-scanner")

_SEV = {
    "CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3", "UNKNOWN": "P3",
    "critical": "P0", "high": "P1", "medium": "P2", "low": "P3",
    "error": "P1", "warning": "P2", "note": "P3",
}


def _sev(value, default="P2"):
    if not value:
        return default
    return _SEV.get(str(value), _SEV.get(str(value).upper(), default))


def _run(cmd, timeout=90):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _which(name):
    return shutil.which(name)


def run_adapters(path, enabled=True):
    """Return (findings, tool_rows). tool_rows are {name, status, detail}."""
    rows, findings = [], []
    if not enabled:
        return findings, [{"name": n, "status": "not run", "detail": "adapters disabled"} for n in TOOLS]
    runners = {
        "trivy": _trivy,
        "gitleaks": _gitleaks,
        "zizmor": _zizmor,
        "checkov": _checkov,
        "osv-scanner": _osv,
    }
    for name in TOOLS:
        if not _which(name):
            rows.append({"name": name, "status": "not run", "detail": "not on PATH"})
            continue
        try:
            got, detail = runners[name](path)
            findings.extend(got)
            rows.append({"name": name, "status": "ran", "detail": detail or f"{len(got)} findings"})
        except Exception as exc:
            rows.append({"name": name, "status": "not run", "detail": f"error: {exc}"[:200]})
    return findings, rows


def dedupe(ours, extras):
    """Drop an adapter finding when we already reported the same file for a related check.

    zizmor `unpinned-uses` overlaps NEW-CICD-ACTION-PIN. Same for other pin/secret pairs
    that name the same workflow or Dockerfile.
    """
    owned_files = []
    for f in ours:
        ev = (f.get("evidence") or "") + " " + (f.get("resource") or "")
        owned_files.append((f, ev))
    kept = []
    for e in extras:
        blob = " ".join(str(e.get(k) or "") for k in ("evidence", "resource", "title", "check_id"))
        drop = False
        for o, ev in owned_files:
            if not ev.strip():
                continue
            names = _names(ev) | _names(o.get("resource") or "")
            path_hit = bool(names & _names(blob)) or any(
                part and part in blob for part in ev.split() if "/" in part or part.endswith((".tf", ".yml", ".yaml", ".json"))
            )
            if path_hit and _theme(o) and _theme(o) == _theme(e):
                drop = True
                break
            if path_hit and o.get("check_id") == "NEW-CICD-ACTION-PIN" and "unpinned" in (e.get("check_id") or "").lower():
                drop = True
                break
        if not drop:
            kept.append(e)
    return kept


def _names(text):
    return set(re.findall(r"[\w.@-]+\.(?:yml|yaml|tf|json|Dockerfile)", str(text))) | (
        {"Dockerfile"} if "Dockerfile" in str(text) else set()
    )


def _theme(f):
    cid = (f.get("check_id") or "").lower()
    title = (f.get("title") or "").lower()
    blob = cid + " " + title
    if any(w in blob for w in ("secret", "token", "password", "credential", "gitleaks")):
        return "secret"
    if any(w in blob for w in ("unpinned", "pin", "latest", "digest")):
        return "pin"
    return ""


def _trivy(path):
    p = _run(["trivy", "fs", "--offline-scan", "--scanners", "vuln,misconfig,secret", "--format", "json", "--quiet", path])
    data = _json(p.stdout)
    out = []
    for res in (data or {}).get("Results") or []:
        target = res.get("Target") or path
        for v in res.get("Vulnerabilities") or []:
            out.append(_f("trivy", f"trivy:{v.get('VulnerabilityID', 'vuln')}", os.path.basename(str(target)),
                          f"{v.get('VulnerabilityID')} {v.get('PkgName', '')} {v.get('Title', '')}".strip(),
                          _sev(v.get("Severity")), target, (v.get("CauseMetadata") or {}).get("StartLine")))
        for m in res.get("Misconfigurations") or []:
            line = ((m.get("CauseMetadata") or {}).get("StartLine"))
            out.append(_f("trivy", f"trivy:{m.get('ID', 'misconfig')}", os.path.basename(str(target)), m.get("Title") or m.get("Message") or "misconfig",
                          _sev(m.get("Severity")), target, line))
        for s in res.get("Secrets") or []:
            line = s.get("StartLine")
            sev = "P3" if noise_path(target) else _sev(s.get("Severity"), "P1")
            out.append(_f("trivy", f"trivy:{s.get('RuleID', 'secret')}", os.path.basename(str(target)), s.get("Title") or "secret", sev, target, line))
    return out, f"{len(out)} normalized"


def _gitleaks(path):
    fd, report = tempfile.mkstemp(prefix="roqy-gitleaks-", suffix=".json")
    os.close(fd)
    try:
        _run(["gitleaks", "detect", "--no-git", "--source", path, "--report-format", "json", "--report-path", report, "--exit-code", "0"])
        raw = open(report, encoding="utf-8").read() if os.path.getsize(report) else "[]"
        data = _json(raw) or []
    finally:
        try:
            os.remove(report)
        except OSError:
            pass
    out = []
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or []
    for item in data:
        rule = item.get("RuleID") or item.get("rule") or "secret"
        file = item.get("File") or item.get("file") or path
        line = item.get("StartLine") or item.get("startLine") or item.get("line")
        sev = "P3" if noise_path(file) else "P1"
        out.append(_f("gitleaks", f"gitleaks:{rule}", os.path.basename(str(file)), f"gitleaks {rule}", sev, file, line))
    return out, f"{len(out)} normalized"


def _zizmor(path):
    p = _run(["zizmor", "--offline", "--format", "json", path])
    data = _json(p.stdout) or {}
    out = []
    results = data.get("results") if isinstance(data, dict) else data
    if isinstance(data, dict) and not results:
        # SARIF-ish
        for run in data.get("runs") or []:
            results = (results or []) + (run.get("results") or [])
    for item in results or []:
        if not isinstance(item, dict):
            continue
        rule = item.get("rule") or item.get("ruleId") or item.get("ident") or "workflow"
        msg = item.get("message") or item.get("desc") or rule
        if isinstance(msg, dict):
            msg = msg.get("text") or rule
        loc, line = _sarif_loc(item)
        if not loc:
            loc = item.get("path") or item.get("file") or path
        out.append(_f("zizmor", f"zizmor:{rule}", os.path.basename(str(loc)), str(msg)[:180], _sev(item.get("severity") or item.get("level"), "P2"), str(loc), line))
    return out, f"{len(out)} normalized"


def _checkov(path):
    p = _run(["checkov", "-d", path, "--quiet", "-o", "json", "--download-external-modules", "false"])
    data = _json(p.stdout)
    checks = []
    if isinstance(data, list):
        for block in data:
            checks.extend((block or {}).get("results", {}).get("failed_checks") or [])
    elif isinstance(data, dict):
        checks = (data.get("results") or {}).get("failed_checks") or []
    out = []
    for c in checks:
        cid = c.get("check_id") or "CKV"
        where = c.get("file_path") or c.get("repo_file_path") or path
        span = c.get("file_line_range") or []
        line = span[0] if isinstance(span, list) and span else None
        out.append(_f("checkov", f"checkov:{cid}", os.path.basename(str(where)), c.get("check_name") or cid, _sev(c.get("severity"), "P2"), str(where), line))
    return out, f"{len(out)} normalized"


def _osv(path):
    p = _run(["osv-scanner", "--offline", "--format", "json", path])
    data = _json(p.stdout) or {}
    out = []
    for res in data.get("results") or []:
        source = ((res.get("source") or {}).get("path")) or path
        for pkg in res.get("packages") or []:
            name = ((pkg.get("package") or {}).get("name")) or "package"
            for v in pkg.get("vulnerabilities") or []:
                vid = v.get("id") or "OSV"
                out.append(_f("osv-scanner", f"osv-scanner:{vid}", name, f"{vid} in {name}", "P2", source))
    return out, f"{len(out)} normalized"


def _json(text):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # some tools print a log line before JSON
        i = text.find("{")
        j = text.find("[")
        start = min([n for n in (i, j) if n >= 0], default=-1)
        if start < 0:
            return None
        try:
            return json.loads(text[start:])
        except json.JSONDecodeError:
            return None


def _sarif_loc(item):
    locs = item.get("locations") or []
    if not locs or not isinstance(locs[0], dict):
        return None, None
    phys = (locs[0].get("physicalLocation") or {})
    art = (phys.get("artifactLocation") or {}).get("uri")
    region = phys.get("region") or {}
    return art, region.get("startLine")


def _f(tool, check_id, resource, title, severity, evidence, line=None):
    ev = str(evidence or "")
    if line and not ev.endswith(f":{line}"):
        ev = f"{ev}:{line}"
    return {
        "check_id": check_id,
        "resource": resource,
        "title": title[:240],
        "severity": severity,
        "status": "needs_validation",
        "evidence": ev,
        "line": line,
        "layer": "adapter",
        "tool": tool,
    }
