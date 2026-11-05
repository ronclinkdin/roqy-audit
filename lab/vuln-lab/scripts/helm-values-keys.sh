#!/usr/bin/env bash
# CLIENT-SIDE helper (run by the client, not by roqy): lists Helm release value KEYS that look like secrets.
# Never prints values. roqy's view-only role cannot read sh.helm.release.v1.* Secrets, so this is how the
# NEW-HELM-VALUES-SECRETS finding gets validated without anyone sending us a secret.
# Usage: KUBE_CONTEXT=<ctx> ./helm-values-keys.sh
set -euo pipefail
: "${KUBE_CONTEXT:?set KUBE_CONTEXT explicitly}"
helm --kube-context "$KUBE_CONTEXT" list -A -o json | python3 -c '
import json,sys,subprocess,re
R=re.compile(r"pass|secret|token|api.?key|private|credential|dsn",re.I)
def walk(d,p=""):
  if isinstance(d,dict):
    for k,v in d.items(): yield from walk(v,f"{p}.{k}" if p else k)
  elif isinstance(d,list):
    for i,v in enumerate(d): yield from walk(v,f"{p}[{i}]")
  else: yield p,d
for r in json.load(sys.stdin):
  out=subprocess.run(["helm","--kube-context",sys.argv[1],"get","values",r["name"],"-n",r["namespace"],"--all","-o","json"],capture_output=True,text=True).stdout or "{}"
  keys=[k for k,v in walk(json.loads(out)) if R.search(k) and v not in (None,"")]
  print("%s/%s rev %s: %d secret-like keys: %s" % (r["namespace"], r["name"], r["revision"], len(keys), keys))
' "$KUBE_CONTEXT"
