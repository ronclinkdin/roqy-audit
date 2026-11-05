#!/usr/bin/env python3
"""Client-side state redactor for roqy drift checks. The CLIENT runs this; roqy never gets raw state.
   terraform state pull | python3 redact-state.py > state.redacted.json
Keeps: resource addresses, types, ids/arns, and non-secret attributes needed for drift
(security group rules, tags, names). Drops: every attribute Terraform marks sensitive, every key that looks
like a secret, every output value, and any string that looks like a credential."""
import json, re, sys
KEY_RE = re.compile(r"pass|secret|token|private|key_material|credential|value$|^value|user_data|certificate_body", re.I)
VAL_RE = re.compile(r"AKIA[0-9A-Z]{16}|sk_live_|ghp_|-----BEGIN|://[^/\s:]+:[^@\s]+@")
def paths(sens):  # sensitive_attributes: [[{"type":"get_attr","value":"password"}, ...], ...]  (TF>=1.10 may use a dict form)
    out = set()
    for p in sens or []:
        if isinstance(p, list) and p and isinstance(p[0], dict): out.add(str(p[0].get("value")))
        elif isinstance(p, dict) and p.get("type") == "get_attr": out.add(str(p.get("value")))
    return out
def clean(v, drop):
    if isinstance(v, dict):
        return {k: ("<redacted>" if (k in drop or KEY_RE.search(k)) else clean(x, set())) for k, x in v.items()}
    if isinstance(v, list): return [clean(x, set()) for x in v]
    if isinstance(v, str) and VAL_RE.search(v): return "<redacted>"
    return v
st = json.load(sys.stdin)
res = []
for r in st.get("resources", []):
    if r.get("mode") != "managed": continue
    for inst in r.get("instances", []):
        res.append({"address": ".".join(x for x in [r.get("module"), r["type"], r["name"]] if x) + (f"[{json.dumps(inst['index_key'])}]" if "index_key" in inst else ""),
                    "type": r["type"], "attributes": clean(inst.get("attributes", {}), paths(inst.get("sensitive_attributes")))})
json.dump({"terraform_version": st.get("terraform_version"), "serial": st.get("serial"), "outputs": sorted(st.get("outputs", {})),
           "resources": res}, sys.stdout, indent=1)
