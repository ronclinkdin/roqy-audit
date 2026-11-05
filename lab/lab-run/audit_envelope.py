#!/usr/bin/env python3
"""roqy-audit ENVELOPE checks (c19-c25): Terraform state/backend, drift, IaC supply chain, CI/CD,
Kubernetes workloads/RBAC, Helm, cross-layer chains, Docker/deps & AI-agent supply chain.

Read-only by construction:
  * AWS calls only through the read-only audit role (roqy-audit-sandbox via ro env); verbs allow-listed.
  * kubectl / helm ALWAYS with --context/--kube-context roqy-lab-audit-ro (view RBAC); verbs allow-listed.
  * Terraform state: bucket METADATA + object key names only (role denies s3:GetObject anyway).
    Drift uses a CLIENT-REDACTED state JSON (scripts/redact-state.py) compared to describe calls;
    terraform itself is never run against the client's backend.
  * Secrets: only names/keys are ever written to findings, never values.
Usage: python3 audit_envelope.py --repo ../vuln-lab/client-repo [--redacted-state envelope/client-state.redacted.json]
"""
import argparse, glob, json, os, re, shutil, subprocess, sys, time, hashlib

def _repo_root():
    d = os.path.dirname(os.path.abspath(__file__))
    while True:
        if os.path.exists(os.path.join(d, "groundrails.json")) and os.path.isdir(os.path.join(d, "lab")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            raise SystemExit("roqy-audit repo root not found (expected groundrails.json)")
        d = parent

_ROOT = _repo_root()
_LAB = os.path.join(_ROOT, "lab")
OUT = os.environ.get("ENVELOPE_OUT", os.path.join(_LAB, "lab-run", "envelope"))
sys.path.insert(0, os.path.join(_LAB, "harness-loop"))
import guard, overlay  # read-only guardrails + editable surface
os.makedirs(f"{OUT}/raw", exist_ok=True)
RO_ENV = {k: v for k, v in os.environ.items() if k not in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_CONFIG_FILE")}
RO_ENV.update(AWS_CONFIG_FILE=os.path.join(_ROOT, ".auditor-config"),
              AWS_SHARED_CREDENTIALS_FILE=os.path.join(_ROOT, ".auditor-bot-creds"),
              AWS_PROFILE=os.environ.get("AUDIT_PROFILE", "roqy-audit-ro"), AWS_PAGER="", AWS_RETRY_MODE="adaptive", AWS_MAX_ATTEMPTS="8",
              KUBECONFIG=os.environ.get("AUDIT_KUBECONFIG", os.path.join(_ROOT, ".kube", "lab.kubeconfig")))
CTX = os.environ.get("AUDIT_CONTEXT", "roqy-lab-audit-ro")
REGION = "eu-central-1"
AWS_OK = re.compile(r"^(describe|get|list|head|check|lookup|search|batch-get)[a-z0-9-]*$")
F, ERR, GAPS, CMDS = [], [], [], []
SEC_KEY = re.compile(overlay.param("envelope.secret_key_regex", r"pass(word|wd)?|secret|token|api[_.-]?key|private[_.-]?key|credential|stripe|dsn"), re.I)

def find(cid, res, title, sev, status="confirmed", evidence="", layer=""):
    f = overlay.apply(dict(check_id=cid, resource=res, title=title, severity=sev, status=status, evidence=evidence, layer=layer))
    if f: F.append(f)

def log(kind, cmd, rc, err, t, out):
    h = hashlib.md5(" ".join(cmd).encode()).hexdigest()[:8]
    open(f"{OUT}/raw/{kind}-{h}.txt", "w").write(" ".join(cmd) + f"\n---rc={rc}\n" + (out if kind == "aws" else "<k8s output not stored: may contain env literals>") + "\n---stderr\n" + err)
    CMDS.append({"kind": kind, "cmd": " ".join(cmd), "rc": rc, "err": err[:240], "secs": round(time.time() - t, 1)})

def aws(check, args, region=REGION, ok=()):
    svc, op = args[0], args[1]
    assert AWS_OK.match(op), f"non-read verb blocked: {op}"
    cmd = ["aws"] + args + ["--region", region, "--output", "json"]
    guard.check_aws(cmd, RO_ENV)
    t = time.time(); p = subprocess.run(cmd, env=RO_ENV, capture_output=True, text=True, timeout=120)
    log("aws", cmd, p.returncode, p.stderr.strip(), t, p.stdout)
    if p.returncode != 0:
        e = p.stderr.strip()
        if any(o in e for o in ok): return None, e
        if "AccessDenied" in e or "not authorized" in e or "UnauthorizedOperation" in e:
            act = re.search(r"perform: ([a-z0-9-]+:[A-Za-z]+)", e); GAPS.append((check, act.group(1) if act else f"{svc} {op}"))
        ERR.append(f"{check}: aws {svc} {op}: {e[:200]}"); return None, e
    return (json.loads(p.stdout) if p.stdout.strip() else {}), ""

K_OK = {"get", "auth", "version", "api-resources"}
def kube(check, args):
    assert args[0] in K_OK, f"kubectl verb blocked: {args[0]}"
    if args[0] == "get": assert "secret" not in " ".join(args[1:2]).lower(), "never get secrets"
    cmd = ["kubectl", "--context", CTX] + args
    guard.check_kubectl(cmd)
    t = time.time(); p = subprocess.run(cmd, env=RO_ENV, capture_output=True, text=True, timeout=120)
    log("kubectl", cmd, p.returncode, p.stderr.strip(), t, "")
    if p.returncode != 0:
        e = p.stderr.strip()
        if "Forbidden" in e or "forbidden" in e: GAPS.append((check, "k8s RBAC: " + (re.search(r'cannot (\w+ resource "[^"]+")', e) or re.search("(.*)", e)).group(1)[:90]))
        ERR.append(f"{check}: kubectl {' '.join(args[:3])}: {e[:200]}"); return None
    return json.loads(p.stdout) if "-o" in args and "json" in args else p.stdout

def helm(check, args):
    assert args[0] in ("list", "status", "version"), f"helm verb blocked: {args[0]}"
    cmd = ["helm", "--kube-context", CTX] + args
    guard.check_helm(cmd)
    t = time.time(); p = subprocess.run(cmd, env=RO_ENV, capture_output=True, text=True, timeout=120)
    log("helm", cmd, p.returncode, p.stderr.strip(), t, "")
    if p.returncode != 0:
        GAPS.append((check, "helm needs list/get on Secrets (release storage) - not granted by AmazonEKSViewPolicy"))
        ERR.append(f"{check}: helm {' '.join(args)}: {p.stderr.strip()[:200]}"); return None
    return p.stdout

ap = argparse.ArgumentParser()
ap.add_argument("--repo", default=os.path.join(_LAB, "vuln-lab", "client-repo"))
ap.add_argument("--redacted-state", default=f"{OUT}/client-state.redacted.json")
ap.add_argument("--cluster", default="roqy-lab-eks")
ap.add_argument("--static-only", action="store_true", help="repo checks only (clean-repo variant: no AWS/K8s calls)")
A = ap.parse_args()
T0 = time.time()
REPO = os.path.abspath(A.repo)

# =====================================================================================
# 1. REPO (static, like infra-readiness-audit): Terraform + workflows + helmfile
# =====================================================================================
_src = os.path.join(_ROOT, "src")
if _src not in sys.path:
    sys.path.insert(0, _src)
from roqy_audit.repo_scan import scan_static
backend = scan_static(REPO, find, SEC_KEY, overlay.param)

if A.static_only:
    json.dump({"findings": [dict(id=f"E{i+1}", **f) for i, f in enumerate(F)], "errors": ERR, "permission_gaps": [], "runtime_s": round(time.time() - T0), "static_only": True},
              open(f"{OUT}/findings-envelope.json", "w"), indent=1, default=str)
    json.dump(CMDS, open(f"{OUT}/commands-envelope.json", "w"), indent=1)
    print(len(F), "findings (static-only);", round(time.time() - T0), "s"); sys.exit(0)

# =====================================================================================
# 2. TERRAFORM STATE BUCKET (metadata only; RO role cannot GetObject)
# =====================================================================================
state_buckets = set()
if backend and backend.get("bucket"): state_buckets.add(backend["bucket"])
bl, _ = aws("NEW-TF-STATE", ["s3api", "list-buckets"])
for b in (bl or {}).get("Buckets", []):
    if re.search(r"tfstate|terraform|tf-state", b["Name"], re.I): state_buckets.add(b["Name"])
ACCT = (aws("ACCT", ["sts", "get-caller-identity"])[0] or {}).get("Account", "")
STATE_FACTS = {}
for b in sorted(state_buckets):
    # region of the bucket
    loc, _ = aws("NEW-TF-STATE", ["s3api", "get-bucket-location", "--bucket", b])
    reg = (loc or {}).get("LocationConstraint") or "us-east-1"
    ls, _ = aws("NEW-TF-STATE", ["s3api", "list-objects-v2", "--bucket", b, "--max-items", "200", "--query", "Contents[].Key"], reg)
    keys = [k for k in (ls or []) if str(k).endswith((".tfstate", ".tfstate.backup", ".tflock"))] if isinstance(ls, list) else []
    if not keys and b != (backend or {}).get("bucket"): continue
    facts = STATE_FACTS.setdefault(b, {"keys": keys})
    v, _ = aws("NEW-TF-STATE-VERSIONING", ["s3api", "get-bucket-versioning", "--bucket", b], reg)
    if (v or {}).get("Status") != "Enabled":
        facts["no_versioning"] = True
        find("NEW-TF-STATE-VERSIONING", b, f"State bucket {b} ({len(keys)} state objects: {', '.join(keys[:5])}) has versioning {(v or {}).get('Status', 'never enabled')}", "P1", layer="iac")
    e, _ = aws("NEW-TF-STATE-ENCRYPTION", ["s3api", "get-bucket-encryption", "--bucket", b], reg, ok=("ServerSideEncryptionConfigurationNotFound",))
    algos = [r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] for r in (e or {}).get("ServerSideEncryptionConfiguration", {}).get("Rules", [])]
    pol, _ = aws("NEW-TF-STATE-ACCESS", ["s3api", "get-bucket-policy", "--bucket", b], reg, ok=("NoSuchBucketPolicy",))
    doc = json.loads(pol["Policy"]) if pol else {"Statement": []}
    st = doc["Statement"] if isinstance(doc["Statement"], list) else [doc["Statement"]]
    tls_deny = any(s.get("Effect") == "Deny" and "aws:SecureTransport" in json.dumps(s.get("Condition", {})) for s in st)
    if not any(a.startswith("aws:kms") for a in algos):
        find("NEW-TF-STATE-ENCRYPTION", b, f"State bucket {b}: encryption {algos or 'none'} only (no SSE-KMS key gate){', backend encrypt=false' if (backend or {}).get('encrypt') == 'false' else ''}{'' if tls_deny else ', no TLS-only deny'}", "P2", layer="iac")
    for s in st:
        if s.get("Effect") != "Allow": continue
        acts = [a.lower() for a in ([s["Action"]] if isinstance(s.get("Action"), str) else s.get("Action", []))]
        reads = any(a in ("s3:getobject", "s3:*", "*", "s3:get*") for a in acts)
        pr = s.get("Principal"); cond = json.dumps(s.get("Condition", {}))
        star = pr == "*" or (isinstance(pr, dict) and pr.get("AWS") in ("*", ["*"]))
        root = isinstance(pr, dict) and re.search(r":root\"?$", json.dumps(pr.get("AWS", "")).rstrip('"]'))
        narrowing = re.search(r"aws:Principal(Arn|Tag)|aws:userid|aws:SourceVpce|aws:SourceIp", cond)
        if reads and ((star and not narrowing) or (root and not narrowing)):
            scope = "any principal in the account" if "PrincipalAccount" in cond else ("any principal in the org" if "PrincipalOrgID" in cond else ("account root (= every IAM principal with s3 perms)" if root else "ANYONE"))
            w = " and can overwrite it" if any(a in ("s3:putobject", "s3:*", "*") for a in acts) else ""
            facts["broad"] = scope
            find("NEW-TF-STATE-ACCESS", b, f"State bucket {b} policy '{s.get('Sid', '')}' lets {scope} read state{w}", "P1", layer="iac")
    if backend and b == backend.get("bucket") and "dynamodb_table" in backend:
        aws("NEW-TF-STATE-LOCK", ["dynamodb", "describe-table", "--table-name", backend["dynamodb_table"]], reg)

# =====================================================================================
# 3. DRIFT: client-shared REDACTED state vs live describe calls (no terraform run, no state read)
# =====================================================================================
DRIFT_MODE = "redacted-state-vs-describe"
if os.path.exists(A.redacted_state):
    rs = json.load(open(A.redacted_state))
    def norm_rules(rules):
        out = set()
        for r in rules or []:
            for c in (r.get("cidr_blocks") or []): out.add((r["protocol"], r["from_port"], r["to_port"], c))
            for c in (r.get("ipv6_cidr_blocks") or []): out.add((r["protocol"], r["from_port"], r["to_port"], c))
            for g in (r.get("security_groups") or []): out.add((r["protocol"], r["from_port"], r["to_port"], g))
        return out
    arn_map = {}
    for r in rs["resources"]:
        at = r["attributes"]
        if at.get("arn"): arn_map[at["arn"]] = r
        if r["type"] == "aws_security_group":
            d, _ = aws("NEW-TF-DRIFT-SECURITY", ["ec2", "describe-security-groups", "--group-ids", at["id"]])
            if not d: continue
            live = set()
            for ip in d["SecurityGroups"][0]["IpPermissions"]:
                for c in ip.get("IpRanges", []): live.add((ip["IpProtocol"], ip.get("FromPort", 0), ip.get("ToPort", 0), c["CidrIp"]))
                for c in ip.get("Ipv6Ranges", []): live.add((ip["IpProtocol"], ip.get("FromPort", 0), ip.get("ToPort", 0), c["CidrIpv6"]))
                for g in ip.get("UserIdGroupPairs", []): live.add((ip["IpProtocol"], ip.get("FromPort", 0), ip.get("ToPort", 0), g["GroupId"]))
            code = norm_rules(at.get("ingress"))
            added, removed = live - code, code - live
            if added or removed:
                world = [x for x in added if x[3] in ("0.0.0.0/0", "::/0")]
                find("NEW-TF-DRIFT-SECURITY", at.get("name", at["id"]), f"{r['address']} ({at.get('name')}, {at['id']}): live ingress differs from Terraform: added out-of-band {sorted(added)}, missing {sorted(removed)}",
                     "P1" if world else "P2", evidence=os.path.basename(A.redacted_state), layer="drift")
    # generic tag drift over every ARN in state (tagging API = read-only)
    arns = list(arn_map)
    for i in range(0, len(arns), 20):
        d, _ = aws("NEW-TF-DRIFT", ["resourcegroupstaggingapi", "get-resources", "--resource-arn-list", *arns[i:i + 20]])
        for m in (d or {}).get("ResourceTagMappingList", []):
            r = arn_map.get(m["ResourceARN"]);
            if not r: continue
            live = {t["Key"]: t["Value"] for t in m["Tags"]}
            code = r["attributes"].get("tags_all") or r["attributes"].get("tags") or {}
            diff = {k: (code.get(k), live.get(k)) for k in set(code) | set(live) if code.get(k) != live.get(k) and not k.startswith("aws:")}
            if diff:
                nm = r["attributes"].get("name") or r["attributes"].get("id")
                find("NEW-TF-DRIFT", nm, f"{r['address']} ({nm}): tags changed outside Terraform: " + ", ".join(f"{k}: {a!r} -> {b!r}" for k, b2 in [(k, v) for k, v in diff.items()] for a, b in [b2]), "P3", evidence="tagging API", layer="drift")
else:
    find("NEW-TF-DRIFT", "terraform-state", "Drift not checked: no client-shared redacted state (scripts/redact-state.py)", "P3", status="needs_validation", layer="drift")

# =====================================================================================
# 4. KUBERNETES (view RBAC, explicit context) + EKS/IAM side
# =====================================================================================
cl, _ = aws("NEW-K8S", ["eks", "describe-cluster", "--name", A.cluster])
K = {}
if cl:
    pods = kube("NEW-K8S", ["get", "pods", "-A", "-o", "json"]) or {"items": []}
    sas = kube("NEW-K8S", ["get", "serviceaccounts", "-A", "-o", "json"]) or {"items": []}
    nps = kube("NEW-K8S-NETPOL", ["get", "networkpolicies", "-A", "-o", "json"]) or {"items": []}
    deps = kube("NEW-K8S", ["get", "deployments,daemonsets,statefulsets", "-A", "-o", "json"]) or {"items": []}
    cms = kube("NEW-HELM", ["get", "configmaps", "-A", "-o", "json"]) or {"items": []}
    SYS = {"kube-system", "kube-public", "kube-node-lease", "amazon-cloudwatch", "cert-manager"}
    owned = lambda p: any(o.get("kind") in ("ReplicaSet", "DaemonSet", "StatefulSet", "Job") for o in p["metadata"].get("ownerReferences", []))
    np_ns = {n["metadata"]["namespace"] for n in nps["items"]}
    egress_blocks_imds = {n["metadata"]["namespace"] for n in nps["items"] if "Egress" in n["spec"].get("policyTypes", []) and "169.254.169.254" in json.dumps(n["spec"].get("egress", []))}
    K.update(priv=[], hostnet=[], hostpath=[], app_pods=[])
    for p in pods["items"]:
        ns, nm = p["metadata"]["namespace"], p["metadata"]["name"]
        if ns in SYS: continue
        s = p["spec"]; full = f"{ns}/{nm}"
        label = p["metadata"].get("annotations", {}).get("meta.helm.sh/release-name") or (nm.rsplit("-", 2)[0] if owned(p) else nm)
        K["app_pods"].append(full)
        if owned(p) and any(x["metadata"]["namespace"] == ns and x["kind"] == "Deployment" and x["metadata"]["name"] == label for x in deps["items"]):
            continue  # judged at the Deployment level below
        ctrs = s.get("containers", []) + s.get("initContainers", [])
        if any((c.get("securityContext") or {}).get("privileged") for c in ctrs):
            K["priv"].append(full); find("NEW-K8S-PRIVILEGED", nm, f"Pod {full}: privileged container (root on node {s.get('nodeName', '?')})", "P1", layer="k8s")
        hp = [v["hostPath"]["path"] for v in s.get("volumes", []) if "hostPath" in v]
        if hp:
            K["hostpath"].append(full); find("NEW-K8S-HOSTPATH", nm, f"Pod {full}: hostPath mounts {hp}", "P1" if "/" in hp or any(x in ("/var/run/docker.sock", "/var/lib/kubelet", "/etc") for x in hp) else "P2", layer="k8s")
        if s.get("hostNetwork"):
            K["hostnet"].append(full); find("NEW-K8S-HOSTNETWORK", nm, f"Pod {full}: hostNetwork=true (node IMDS + kubelet reachable, NetworkPolicy bypassed)", "P2", layer="k8s")
    for obj in [p for p in pods["items"] if not owned(p)] + deps["items"]:
        ns, nm = obj["metadata"]["namespace"], obj["metadata"]["name"]
        if ns in SYS: continue
        s = obj["spec"]["template"]["spec"] if obj["kind"] != "Pod" else obj["spec"]
        kind = obj["kind"]
        for c in s.get("containers", []):
            img = c["image"]; tag = img.rsplit(":", 1)[1] if ":" in img.split("/")[-1] else ""
            if "@sha256:" not in img and tag in ("", "latest"):
                find("NEW-K8S-IMAGE-LATEST", nm, f"{kind} {ns}/{nm}: image {img} (tag {'latest' if tag else 'none'}, mutable{', public Docker Hub' if img.startswith(('docker.io', 'busybox', 'library/')) else ''})", "P3", layer="k8s")
            if not (c.get("resources") or {}).get("limits"):
                find("NEW-K8S-NO-LIMITS", nm, f"{kind} {ns}/{nm}: container {c['name']} has no resource limits", "P3", layer="k8s")
            for e in c.get("env", []):
                if (e.get("valueFrom") or {}).get("secretKeyRef") and kind == "Pod":
                    r = e["valueFrom"]["secretKeyRef"]
                    find("NEW-K8S-SECRET-ENV", nm, f"Pod {ns}/{nm}: secret {r['name']}/{r['key']} injected as env {e['name']} (names only)", "P3", layer="k8s")
    # service accounts: IRSA + default automount
    for sa in sas["items"]:
        ns, nm = sa["metadata"]["namespace"], sa["metadata"]["name"]
        if ns in SYS: continue
        ra = sa["metadata"].get("annotations", {}).get("eks.amazonaws.com/role-arn")
        if ra:
            rn = ra.split("/")[-1]; broad, bnd = [], None
            pl, _ = aws("NEW-K8S-IRSA-BROAD", ["iam", "list-role-policies", "--role-name", rn])
            for pn in (pl or {}).get("PolicyNames", []):
                d, _ = aws("NEW-K8S-IRSA-BROAD", ["iam", "get-role-policy", "--role-name", rn, "--policy-name", pn])
                for s in ((d or {}).get("PolicyDocument", {}).get("Statement", [])):
                    acts = [s["Action"]] if isinstance(s.get("Action"), str) else s.get("Action", [])
                    if s.get("Effect") == "Allow" and "*" in json.dumps(s.get("Resource")) and any(a == "*" or a.endswith(":*") for a in acts): broad += acts
            at, _ = aws("NEW-K8S-IRSA-BROAD", ["iam", "list-attached-role-policies", "--role-name", rn])
            broad += [p["PolicyName"] for p in (at or {}).get("AttachedPolicies", []) if re.search(r"Admin|FullAccess|PowerUser", p["PolicyName"])]
            rr, _ = aws("NEW-K8S-IRSA-BROAD", ["iam", "get-role", "--role-name", rn, "--query", "Role.PermissionsBoundary"])
            if broad:
                find("NEW-K8S-IRSA-BROAD", nm, f"ServiceAccount {ns}/{nm} -> IRSA role {rn} with {sorted(set(broad))} on *{' (permissions boundary ' + rr['PermissionsBoundaryArn'].split('/')[-1] + ' present: verify it really limits)' if rr else ''}", "P1", layer="k8s")
        if nm == "default" and sa.get("automountServiceAccountToken") is not False:
            users = [p["metadata"]["name"] for p in pods["items"] if p["metadata"]["namespace"] == ns and p["spec"].get("serviceAccountName", "default") == "default" and p["spec"].get("automountServiceAccountToken") is not False]
            if users:
                find("NEW-K8S-SA-AUTOMOUNT", f"{ns}/default", f"{ns}/default SA token automounted into {len(users)} pod(s): {', '.join(users[:5])}", "P3", layer="k8s")
    pia, _ = aws("NEW-K8S-IRSA-BROAD", ["eks", "list-pod-identity-associations", "--cluster-name", A.cluster])
    K["pod_identity"] = len((pia or {}).get("associations", []))
    for ns in sorted({p.split("/")[0] for p in K["app_pods"]}):
        if ns not in np_ns:
            find("NEW-K8S-NETPOL", ns, f"Namespace {ns}: {sum(p.startswith(ns + '/') for p in K['app_pods'])} pods, zero NetworkPolicy (flat network, IMDS egress open)", "P2", layer="k8s")
    # RBAC (needs a reader group; view cannot list RBAC)
    crb = kube("NEW-K8S-RBAC-ADMIN", ["get", "clusterrolebindings", "-o", "json"])
    rb = kube("NEW-K8S-RBAC-ADMIN", ["get", "rolebindings", "-A", "-o", "json"])
    K["rbac_readable"] = crb is not None
    for b in ((crb or {}).get("items", []) + (rb or {}).get("items", [])):
        if b["roleRef"]["name"] not in ("cluster-admin", "admin", "edit"): continue
        for s in b.get("subjects") or []:
            if s["kind"] == "ServiceAccount" and s.get("namespace") not in SYS:
                find("NEW-K8S-RBAC-ADMIN", b["metadata"]["name"], f"{b['kind']} {b['metadata']['name']}: {b['roleRef']['name']} -> ServiceAccount {s.get('namespace')}/{s['name']}", "P0" if b["roleRef"]["name"] == "cluster-admin" else "P1", layer="k8s")
    if crb is None:
        find("NEW-K8S-RBAC-ADMIN", "rbac", "RBAC bindings NOT audited: AmazonEKSViewPolicy cannot list (Cluster)RoleBindings - grant group roqy-audit-rbac-read", "P3", status="needs_validation", layer="k8s")
    # IMDS reachability from pods: node metadata options (+ no egress block)
    ng, _ = aws("NEW-K8S-IMDS", ["eks", "list-nodegroups", "--cluster-name", A.cluster])
    inst, _ = aws("NEW-K8S-IMDS", ["ec2", "describe-instances", "--filters", f"Name=tag:eks:cluster-name,Values={A.cluster}", "Name=instance-state-name,Values=running",
                                    "--query", "Reservations[].Instances[].{i:InstanceId,m:MetadataOptions,ng:Tags[?Key=='eks:nodegroup-name']|[0].Value,p:IamInstanceProfile.Arn}"])
    K["nodes"] = inst or []
    for n in inst or []:
        hop, tok = n["m"].get("HttpPutResponseHopLimit", 1), n["m"].get("HttpTokens")
        open_ns = [ns for ns in {p.split("/")[0] for p in K["app_pods"]} if ns not in egress_blocks_imds]
        if n["m"].get("HttpEndpoint") == "enabled" and (hop >= 2 or tok == "optional") and open_ns:
            find("NEW-K8S-IMDS", n["ng"] or n["i"], f"Node group {n['ng']} node {n['i']}: IMDS hop limit {hop}, tokens {tok}, no egress policy to 169.254.169.254 in {sorted(open_ns)}: every pod can take the node role", "P1", layer="k8s")
            K.setdefault("imds_nodes", []).append(n)
    # Helm: release storage is Secrets -> not readable with view. Detect releases via labels, values-secrets via rendered objects.
    helm("NEW-HELM-VALUES-SECRETS", ["list", "-A", "-o", "json"])
    rel_objs = {}
    for o in deps["items"] + cms["items"]:
        rn = o["metadata"].get("annotations", {}).get("meta.helm.sh/release-name")
        if rn: rel_objs.setdefault((o["metadata"]["namespace"], rn), []).append(o)
    for (ns, rn), objs in rel_objs.items():
        leaked = []
        for o in objs:
            if o["kind"] == "ConfigMap":
                ks = [k for k, v in (o.get("data") or {}).items() if SEC_KEY.search(k) and v]
                if ks: leaked.append(f"ConfigMap {o['metadata']['name']} keys {ks}")
                if ks: find("NEW-HELM-PLAINTEXT-RENDERED", o["metadata"]["name"], f"Helm release {ns}/{rn}: ConfigMap {o['metadata']['name']} holds secret-like keys {ks} in plaintext (values not shown)", "P1", layer="helm")
            else:
                for c in o["spec"]["template"]["spec"].get("containers", []):
                    ks = [e["name"] for e in c.get("env", []) if SEC_KEY.search(e["name"]) and e.get("value")]
                    if ks:
                        leaked.append(f"{o['kind']} {o['metadata']['name']} env {ks}")
                        find("NEW-HELM-PLAINTEXT-RENDERED", o["metadata"]["name"] + "-env", f"Helm release {ns}/{rn}: {o['kind']} {o['metadata']['name']} has literal secret env {ks} (values not shown)", "P1", layer="helm")
        if leaked:
            find("NEW-HELM-VALUES-SECRETS", rn, f"Helm release {ns}/{rn}: rendered objects carry plaintext secrets ({'; '.join(leaked)}) => the release values contain them and Helm keeps them in every sh.helm.release.v1.{rn}.v* Secret. Exact value keys need client-side scripts/helm-values-keys.sh (view RBAC cannot read release secrets).",
                 "P1", status="confirmed-by-inference", layer="helm")
    STATE_EKS = cl["cluster"]

# =====================================================================================
# 5. CROSS-LAYER CHAINS (correlation of findings above + cloud facts)
# =====================================================================================
has = lambda cid, **kw: [f for f in F if f["check_id"] == cid and all(v in f[k] for k, v in kw.items())]
for wf in WF:
    a, k = has("NEW-CICD-PR-APPLY", resource=wf), has("NEW-CICD-NO-OIDC", resource=wf)
    if a and k:
        prt = [f["resource"] for f in has("NEW-CICD-PRT-HEAD")]
        find("NEW-CHAIN-CICD-ACCOUNT", wf, f"CHAIN: open a PR -> {wf} runs `terraform apply` with long-lived AWS keys from secrets -> attacker code (providers, modules, local-exec) runs with the deploy identity -> account takeover"
             + (f"; fork PRs get the same keys via {', '.join(prt)} (pull_request_target + head checkout)" if prt else "") + ". Which IAM user owns secrets.AWS_ACCESS_KEY_ID: needs_validation (ask client; check iam list-access-keys last-used from GitHub IPs).", "P0", layer="chain")
for n in K.get("imds_nodes", []):
    role = None
    if n.get("p"):
        ipn = n["p"].split("/")[-1]
        ip, _ = aws("NEW-CHAIN-POD-IMDS-S3", ["iam", "get-instance-profile", "--instance-profile-name", ipn])
        role = ((ip or {}).get("InstanceProfile", {}).get("Roles") or [{}])[0].get("RoleName")
    if not role: continue
    s3 = []
    pl, _ = aws("NEW-CHAIN-POD-IMDS-S3", ["iam", "list-role-policies", "--role-name", role])
    for pn in (pl or {}).get("PolicyNames", []):
        d, _ = aws("NEW-CHAIN-POD-IMDS-S3", ["iam", "get-role-policy", "--role-name", role, "--policy-name", pn])
        for s in (d or {}).get("PolicyDocument", {}).get("Statement", []):
            acts = [s["Action"]] if isinstance(s.get("Action"), str) else s.get("Action", [])
            if s.get("Effect") == "Allow" and s.get("Resource") in ("*", ["*"]) and any(a in ("s3:GetObject", "s3:*", "*", "s3:Get*") for a in acts): s3.append(pn)
    at, _ = aws("NEW-CHAIN-POD-IMDS-S3", ["iam", "list-attached-role-policies", "--role-name", role])
    s3 += [p["PolicyName"] for p in (at or {}).get("AttachedPolicies", []) if re.search(r"S3FullAccess|S3ReadOnly|AdministratorAccess|PowerUser", p["PolicyName"])]
    if s3:
        entry = (K["priv"] + K["hostnet"] + K["hostpath"])[:3]
        find("NEW-CHAIN-POD-IMDS-S3", role, f"CHAIN: compromised pod (easiest: {entry or 'any pod'}) -> node IMDS (hop {n['m']['HttpPutResponseHopLimit']}, no egress policy) -> node role {role} -> s3:GetObject on * via {s3} -> every bucket incl. Terraform state bucket(s) {sorted(STATE_FACTS)}", "P0", layer="chain")
broad_state = [b for b, f in STATE_FACTS.items() if f.get("broad")]
state_secret = has("NEW-TF-STATE-SECRETS")
if broad_state and state_secret:
    # which DB does the client repo point at? (static: variable/host names) -> is it public?
    hosts = set(re.findall(r'"(roqy-lab-[\w-]*db[\w-]*)"', " ".join(tf.values()))) | set(re.findall(r'db_host[^\n]*"([\w.-]+)"', " ".join(tf.values())))
    dbs, _ = aws("NEW-CHAIN-STATE-DB", ["rds", "describe-db-instances", "--query", "DBInstances[].{i:DBInstanceIdentifier,p:PubliclyAccessible,e:Endpoint.Address}"])
    for d in dbs or []:
        if (d["i"] in hosts or any(h.startswith(d["i"]) for h in hosts)) and d["p"]:
            find("NEW-CHAIN-STATE-DB", d["i"], f"CHAIN: state bucket {broad_state[0]} readable by {STATE_FACTS[broad_state[0]]['broad']} -> state holds plaintext DB password ({state_secret[0]['resource']}, output db_url) -> RDS {d['i']} is PubliclyAccessible=true -> direct DB login. Reachability of 5432 depends on SG (needs_validation).", "P1", layer="chain")

# =====================================================================================
out = {"findings": [dict(id=f"E{i+1}", **f) for i, f in enumerate(F)], "errors": ERR, "permission_gaps": sorted(set(GAPS)),
       "drift_mode": DRIFT_MODE, "k8s_context": CTX, "rbac_readable": K.get("rbac_readable"), "pod_identity_associations": K.get("pod_identity"),
       "state_buckets": {b: {k: v for k, v in f.items()} for b, f in STATE_FACTS.items()}, "runtime_s": round(time.time() - T0)}
json.dump(out, open(f"{OUT}/findings-envelope.json", "w"), indent=1, default=str)
json.dump(CMDS, open(f"{OUT}/commands-envelope.json", "w"), indent=1)
print(len(F), "findings;", len(ERR), "errors;", len(set(GAPS)), "permission gaps;", out["runtime_s"], "s")
for g in sorted(set(GAPS)): print("GAP", g)
for e in ERR: print("ERR", e[:180])
