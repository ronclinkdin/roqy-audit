"""roqy-audit command line. Core checks do not use the network."""
import argparse, os, re, shutil, subprocess, sys, tempfile

_SECRET_RE = re.compile(r"pass(word|wd)?|secret|token|api[_.-]?key|private[_.-]?key|credential|stripe|dsn", re.I)

from roqy_audit import __version__
from roqy_audit.adapters import dedupe, run_adapters
from roqy_audit.chains import build_chains
from roqy_audit.report import annotate, fails, to_json, to_markdown, to_sarif
from roqy_audit.repo_scan import scan_static
from roqy_audit.skill_risk import assess

_GIT_URL = re.compile(r"^(https://|http://|git@|ssh://|git://)")


def scan_path(path, use_adapters=True):
    path = os.path.abspath(path)
    if not os.path.isdir(path):
        raise SystemExit(f"not a directory: {path}")
    raw = []

    def find(cid, res, title, sev, status="confirmed", evidence="", layer=""):
        raw.append({
            "check_id": cid, "resource": res, "title": title, "severity": sev,
            "status": status, "evidence": evidence, "layer": layer, "tool": "roqy",
        })

    skipped = []
    scan_static(path, find, _SECRET_RE, skipped=skipped)
    extras, tools = run_adapters(path, enabled=use_adapters)
    ours_tools = [{"name": "roqy-audit", "status": "ran", "detail": f"{len(raw)} static findings"}]
    findings = annotate(raw + dedupe(raw, extras))
    chains = build_chains([f for f in findings if f.get("tool") == "roqy"])
    return {
        "tool": "roqy-audit",
        "version": __version__,
        "target": path,
        "findings": findings,
        "chains": chains,
        "tools": ours_tools + tools,
        "skipped": skipped,
        "disclaimer": "Indicative SOC 2 labels, not an auditor opinion. Static checks did not call the network.",
    }


def _materialize(target):
    """Return a local directory. Git URLs are shallow-cloned. Nothing in the tree is executed."""
    if os.path.isdir(target):
        return os.path.abspath(target), None
    if not _GIT_URL.match(target):
        raise SystemExit(f"not a directory or git URL: {target}")
    dest = tempfile.mkdtemp(prefix="roqy-skill-")
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", target, dest]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise SystemExit(p.stderr.strip() or "git clone failed")
    return dest, dest


def _print_skill(report):
    print(f"[{report['risk'].upper()}] {report['item']} ({report['kind']}, security_topic={report.get('security_topic')})")
    print(f"score={report['score']} counts={report['counts']} files={report['files_scanned']}")
    shown = [f for f in report["findings"] if f["severity"] in ("high", "medium")]
    if not shown:
        print("No high or medium patterns.")
    for f in shown[:25]:
        where = f"{f['file']}:{f['line']}" if f.get("file") else "-"
        print(f"  {f['severity']:6} {f['id']:24} {where}  {f['reason'][:90]}")
    print("WARNING:", report["warning"])


def main(argv=None):
    ap = argparse.ArgumentParser(prog="roqy-audit", description="Static repo scan and pre-install skill risk report.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan a repository path (no network for core checks)")
    sc.add_argument("path", nargs="?", default=".")
    sc.add_argument("--md", help="write the Markdown report to this file (also printed when no file flags are set)")
    sc.add_argument("--json", help="write the JSON report to this file")
    sc.add_argument("--sarif", help="write SARIF 2.1.0 to this file")
    sc.add_argument("--fail-on", default="P1", choices=["P0", "P1", "P2", "P3", "none"],
                    help="exit 1 when a finding or chain is at least this severe (default P1)")
    sc.add_argument("--no-adapters", action="store_true", help="do not run trivy, gitleaks, zizmor, checkov, or osv-scanner")

    sk = sub.add_parser("check-skill", help="pre-install risk report for a skill or MCP server (static; never executes the target)")
    sk.add_argument("target", help="local directory or git URL (shallow clone)")
    sk.add_argument("--name")
    sk.add_argument("--kind", default="auto", choices=["auto", "skill", "mcp"])
    sk.add_argument("--json", help="write the full JSON report")

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        payload = scan_path(args.path, use_adapters=not args.no_adapters)
        md, js, sarif = to_markdown(payload), to_json(payload), to_sarif(payload)
        wrote = False
        if args.md:
            open(args.md, "w", encoding="utf-8").write(md); wrote = True
        if args.json:
            open(args.json, "w", encoding="utf-8").write(js); wrote = True
        if args.sarif:
            open(args.sarif, "w", encoding="utf-8").write(sarif); wrote = True
        if not wrote:
            sys.stdout.write(md)
        return 1 if fails(payload["findings"], payload["chains"], args.fail_on) else 0
    if args.cmd == "check-skill":
        root, cleanup = _materialize(args.target)
        try:
            report = assess(root, name=args.name or (None if cleanup is None else args.target), kind=args.kind, online=False)
        finally:
            if cleanup:
                shutil.rmtree(cleanup, ignore_errors=True)
        if args.json:
            import json
            json.dump(report, open(args.json, "w"), indent=1, default=str)
        _print_skill(report)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
