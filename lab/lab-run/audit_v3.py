"""roqy-audit AWS target check set v3 (repo W-checks fixed + NEW-* checks). Read-only role only."""
import json, re, subprocess, datetime, sys, os, base64, csv, io, time
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
from awsrun import aws
sys.path.insert(0, os.path.join(REPO, "lab", "harness-loop"))
import overlay  # editable surface: severity overrides / disabled checks / knobs
REGIONS = os.environ.get("REGIONS", "eu-central-1,us-east-1").split(",")
HOME = "eu-central-1"
ACCT = open("/tmp/acct").read().strip()
NOW = datetime.datetime.now(datetime.timezone.utc)
F, ERR, GAPS = [], [], []
SECRET_RE = re.compile(overlay.param("secret_name_regex", r"(PASS(WORD)?|SECRET|TOKEN|API_?KEY|PRIVATE|CREDENTIAL|STRIPE|AWS_SECRET)"), re.I)
def find(cid, res, title, sev, status="confirmed", evidence="", consequence="", fix=""):
    f = overlay.apply(dict(check_id=cid, resource=res, title=title, severity=sev, status=status, evidence=evidence, consequence=consequence, fix=fix))
    if f: F.append(f)
def run(cid, args, region=None, ok_errors=(), **kw):
    rc, d, e = aws(cid, args, region, **kw)
    if rc != 0 and not any(x in e for x in ok_errors):
        line = e.splitlines()[-1][:220] if e else f"rc={rc}"
        ERR.append(f"{cid}: aws {' '.join(args[:2])}{' @'+region if region else ''}: {line}")
        if "AccessDenied" in e or "not authorized" in e:
            m = re.search(r"perform: (\S+)", e); GAPS.append((cid, m.group(1) if m else " ".join(args[:2])))
    return rc, d, e
def age_days(ts):
    return (NOW - datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))).days
def stmts(doc):
    s = doc.get("Statement", []) if isinstance(doc, dict) else []
    return [s] if isinstance(s, dict) else s
def aslist(x): return [x] if isinstance(x, str) else (x or [])
def star_principal(pr): return pr == "*" or (isinstance(pr, dict) and "*" in aslist(pr.get("AWS")))
def tagname(tags, default):
    return next((t["Value"] for t in (tags or []) if t["Key"] == "Name"), default)
T0 = time.time()

# ================= S3 =================
_, buckets, _ = run("W1", ["s3api", "list-buckets"])
bnames = [b["Name"] for b in (buckets or {}).get("Buckets", [])]
for b in bnames:
    rc, d, e = run("W1", ["s3api", "get-bucket-policy-status", "--bucket", b], ok_errors=("NoSuchBucketPolicy",))
    if rc == 0 and d["PolicyStatus"]["IsPublic"]: find("W1", b, f"Bucket {b} policy IsPublic=true", "P0")
    rc, d, e = run("W33", ["s3api", "get-bucket-policy", "--bucket", b], ok_errors=("NoSuchBucketPolicy",))
    pol = json.loads(d["Policy"]) if rc == 0 else {}
    for s in stmts(pol):
        if s.get("Effect") != "Allow": continue
        acts = aslist(s.get("Action"))
        if star_principal(s.get("Principal")) and not s.get("Condition") and any(a in ("s3:PutObject", "s3:*", "*") for a in acts):
            find("W33", b, f"Bucket {b} policy lets anyone PutObject", "P0")
        if "AuthenticatedUsers" in json.dumps(s): find("W38", b, f"Bucket {b} grants AuthenticatedUsers", "P1")
        for a in re.findall(r"arn:aws:iam::(\d{12})", json.dumps(s.get("Principal", ""))):
            if a != ACCT: find("NEW-S3-CROSS-ACCOUNT", b, f"Bucket {b} policy grants another account", "P1")
    _, acl, _ = run("W38", ["s3api", "get-bucket-acl", "--bucket", b])
    if "AuthenticatedUsers" in json.dumps(acl or {}) or "AllUsers" in json.dumps(acl or {}):
        find("W38", b, f"Bucket {b} ACL grants AuthenticatedUsers/AllUsers", "P1")
    rc, d, e = run("W27", ["s3api", "get-bucket-notification-configuration", "--bucket", b])
    for a in re.findall(r"arn:aws:[a-z]+:[a-z0-9-]*:(\d{12})", json.dumps(d or {})):
        if a != ACCT: find("W27", b, "S3 event notification to another account", "P1")
    _, ver, _ = run("NEW-S3-RANSOMWARE", ["s3api", "get-bucket-versioning", "--bucket", b])
    rc, ol, e = run("NEW-S3-RANSOMWARE", ["s3api", "get-object-lock-configuration", "--bucket", b], ok_errors=("ObjectLockConfigurationNotFound",))
    if (ver or {}).get("Status") != "Enabled" and rc != 0:
        find("NEW-S3-RANSOMWARE", b, f"Bucket {b}: no versioning, no Object Lock (one DeleteObjects is permanent)", "P1" if "upload" in b or "prod" in b or "backup" in b else "P3")
    rc, enc, e = run("NEW-S3-SSEC", ["s3api", "get-bucket-encryption", "--bucket", b])
    if rc == 0:
        blocked = [t for r in enc["ServerSideEncryptionConfiguration"]["Rules"] for t in (r.get("BlockedEncryptionTypes") or {}).get("EncryptionType", [])]
        if "SSE-C" not in blocked:
            find("NEW-S3-SSEC", b, f"Bucket {b} accepts SSE-C writes (Codefinger re-encryption ransom)", "P1" if "upload" in b or "prod" in b else "P3")
    rc, lc, e = run("NEW-S3-LIFECYCLE-EXPIRY", ["s3api", "get-bucket-lifecycle-configuration", "--bucket", b], ok_errors=("NoSuchLifecycleConfiguration",))
    for r in (lc or {}).get("Rules", []):
        flt = r.get("Filter", {}); whole = not flt or flt == {"Prefix": ""} or r.get("Prefix") == ""
        days = (r.get("Expiration") or {}).get("Days")
        if r.get("Status") == "Enabled" and days and days <= 7 and whole:
            find("NEW-S3-LIFECYCLE-EXPIRY", b, f"Bucket {b} lifecycle '{r.get('ID')}' expires ALL objects after {days}d", "P2")
for b in bnames:
    if re.search(overlay.param("W41.ai_bucket_regex", r"openai|llm|gpt|bedrock|(^|-)ai(-|$)|ml-|model|rag"), b, re.I): find("W41", b, f"AI-named bucket {b}", "P3")
rc, d, e = run("W5", ["s3control", "get-public-access-block", "--account-id", ACCT], ok_errors=("NoSuchPublicAccessBlockConfiguration",))
if rc != 0 or not all(d["PublicAccessBlockConfiguration"].values()):
    find("W5", "account", "Account-level S3 Block Public Access missing or not all four flags on", "P2")

# ================= IAM =================
_, auth, _ = run("W25", ["iam", "get-account-authorization-details"])  # paginated automatically by CLI v2
auth = auth or {}
pol_docs = {p["Arn"]: next(v["Document"] for v in p["PolicyVersionList"] if v["IsDefaultVersion"]) for p in auth.get("Policies", [])}
def entity_docs(ent, lk):
    out = [(ip["PolicyName"], ip["PolicyDocument"]) for ip in ent.get(lk, []) or []]
    for ap in ent.get("AttachedManagedPolicies", []):
        if ap["PolicyArn"] in pol_docs: out.append((ap["PolicyName"], pol_docs[ap["PolicyArn"]]))
        elif ap["PolicyArn"].endswith("/AdministratorAccess"): out.append((ap["PolicyName"], {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}))
    return out
PRIVESC = {"iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:updateassumerolepolicy", "iam:attachuserpolicy", "iam:attachrolepolicy",
           "iam:putuserpolicy", "iam:putrolepolicy", "iam:createaccesskey", "iam:createloginprofile", "iam:updateloginprofile", "iam:addusertogroup", "ssm:sendcommand"}
for kind, lk, nk in (("UserDetailList", "UserPolicyList", "UserName"), ("RoleDetailList", "RolePolicyList", "RoleName"), ("GroupDetailList", "GroupPolicyList", "GroupName")):
    for ent in auth.get(kind, []):
        name = ent[nk]
        if ent.get("Path", "").startswith("/aws-service-role/") or name.startswith(("AWSServiceRole", "aws-")): continue
        for pname, doc in entity_docs(ent, lk):
            for s in stmts(doc):
                if s.get("Effect") != "Allow": continue
                acts = {a.lower() for a in aslist(s.get("Action"))}; res = aslist(s.get("Resource"))
                if "NotAction" in s: find("W25", name, f"{name} / {pname}: Allow NotAction {s['NotAction']} on {res}", "P2")
                if "*" in res and acts & {"iam:passrole", "iam:*"} and not ("*" in acts):
                    find("W24", name, f"{name} / {pname}: iam:PassRole on *", "P1")
                if "*" in acts and "*" in res and kind == "RoleDetailList" and pname not in ("AdministratorAccess",) and not ent.get("Path", "").startswith("/roqy/"):
                    find("NEW-WILDCARD-ADMIN", name, f"Role {name}: policy {pname} Allow * on *", "P1")
                hits = acts & PRIVESC
                if ("iam:passrole" in acts and any(a.startswith(("lambda:create", "ec2:runinstances", "glue:create", "cloudformation:create")) for a in acts)): hits |= {"PassRole+compute"}
                if hits and "*" in res and "*" not in acts:
                    find("NEW-IAM-PRIVESC", name, f"{name}: privilege-escalation primitives on *: {sorted(hits)}", "P1")
_, roles, _ = run("W10", ["iam", "list-roles"])
for ro in (roles or {}).get("Roles", []):
    rn = ro["RoleName"]
    for s in stmts(ro["AssumeRolePolicyDocument"]):
        if s.get("Effect") != "Allow": continue
        pr = s.get("Principal", {}); cond = json.dumps(s.get("Condition", {}))
        if star_principal(pr): find("W10", rn, f"Role {rn} trusts Principal *", "P0")
        for a in aslist(pr.get("AWS") if isinstance(pr, dict) else []):
            m = re.search(r"arn:aws:iam::(\d{12}):(root|user|role)", a)
            if not m: continue
            if m.group(1) != ACCT:
                find("W10", rn, f"Role {rn} trusts external account", "P1")
                if "sts:ExternalId" not in cond: find("W31", rn, f"Role {rn}: cross-account trust without sts:ExternalId", "P1")
            elif m.group(2) == "root" and "sts:ExternalId" not in cond and "aws:PrincipalArn" not in cond and not rn.startswith("roqy-audit"):
                find("W31", rn, f"Role {rn}: trusts an account :root with no ExternalId/PrincipalArn condition (vendor-style trust)", "P1")
        fed = aslist(pr.get("Federated") if isinstance(pr, dict) else [])
        if any("token.actions.githubusercontent.com" in f for f in fed):
            subs = [v for c in (s.get("Condition") or {}).values() for k, v in c.items() if k.endswith(":sub")]
            subs = [x for v in subs for x in aslist(v)]
            if not subs or any(re.fullmatch(r"(repo:)?\*(/\*)?(:\*)?", x) or x.startswith("repo:*") for x in subs):
                find("NEW-OIDC-NO-SUB", rn, f"Role {rn}: GitHub OIDC trust with sub {subs or 'MISSING'} = any GitHub repo can assume", "P0")
        if any("cognito-identity.amazonaws.com" in f for f in fed) and '"unauthenticated"' in cond:
            STATE_UNAUTH = rn
_, users, _ = run("W3", ["iam", "list-users"])
for u in (users or {}).get("Users", []):
    un = u["UserName"]
    _, ks, _ = run("W3", ["iam", "list-access-keys", "--user-name", un])
    _, gu, _ = run("W11", ["iam", "get-user", "--user-name", un])
    pwd_last = (gu or {}).get("User", {}).get("PasswordLastUsed")
    for k in (ks or {}).get("AccessKeyMetadata", []):
        if k["Status"] != "Active": continue
        if age_days(k["CreateDate"]) > overlay.param("W3.max_key_age_days", 90): find("W3", un, f"Active key on {un} older than 90 days", "P2")
        _, lu, _ = run("W11", ["iam", "get-access-key-last-used", "--access-key-id", k["AccessKeyId"]])
        last = (lu or {}).get("AccessKeyLastUsed", {}).get("LastUsedDate")
        if not last:
            find("W11", un, f"User {un}: active access key never used (created {age_days(k['CreateDate'])}d ago) - remove or rotate", "P2")
        elif age_days(last) > 90 and not (pwd_last and age_days(pwd_last) <= 90):
            find("W11", un, f"Dormant user {un}: no activity in 90 days with an active key", "P2")
for v in ("V2", "V3"):
    rc, d, e = run("NEW-KEY-QUARANTINE", ["iam", "list-entities-for-policy", "--policy-arn", f"arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantine{v}"], ok_errors=("NoSuchEntity",))
    for x in (d or {}).get("PolicyUsers", []) + (d or {}).get("PolicyRoles", []):
        n = x.get("UserName") or x.get("RoleName"); find("NEW-KEY-QUARANTINE", n, f"{n} carries AWSCompromisedKeyQuarantine{v}: AWS saw its key leaked", "P0")
run("NEW-CONSOLE-NO-MFA", ["iam", "generate-credential-report"])
cr = None
for _ in range(10):
    rc, cr, e = run("NEW-CONSOLE-NO-MFA", ["iam", "get-credential-report"], ok_errors=("ReportNotPresent", "ReportInProgress"))
    if rc == 0: break
    time.sleep(3)
users_with_pw = 0
if cr:
    for row in csv.DictReader(io.StringIO(base64.b64decode(cr["Content"]).decode())):
        if row["user"] == "<root_account>": continue
        if row["password_enabled"] == "true":
            users_with_pw += 1
            if row["mfa_active"] == "false": find("NEW-CONSOLE-NO-MFA", row["user"], f"Console user {row['user']} has a password and no MFA", "P1")
rc, d, e = run("NEW-PASSWORD-POLICY", ["iam", "get-account-password-policy"], ok_errors=("NoSuchEntity",))
if rc != 0 and "NoSuchEntity" in e: find("NEW-PASSWORD-POLICY", "account", "No IAM account password policy", "P2")
rc, d, e = run("NEW-SSO-ABSENT", ["sso-admin", "list-instances"], HOME)
if rc == 0 and not d.get("Instances") and users_with_pw: find("NEW-SSO-ABSENT", "account", f"No IAM Identity Center while {users_with_pw} IAM users have console passwords", "P3")
_, summ, _ = run("W4", ["iam", "get-account-summary"])
sm = (summ or {}).get("SummaryMap", {})
if sm.get("AccountMFAEnabled") == 0: find("W4", "account", "Root account without MFA", "P0")
if sm.get("AccountAccessKeysPresent") == 1: find("W40", "account", "Root access key exists", "P0")
rc, d, e = run("W16", ["organizations", "describe-organization"], ok_errors=("AWSOrganizationsNotInUse",))
rc, d, e = run("NEW-SECURITY-CONTACT", ["account", "get-alternate-contact", "--alternate-contact-type", "SECURITY"], ok_errors=("ResourceNotFound",))
if rc != 0 and "ResourceNotFound" in e: find("NEW-SECURITY-CONTACT", "account", "No SECURITY alternate contact: AWS abuse/leaked-key notices go only to root email", "P3")

# ================= account-wide logging / guardrails (all regions) =================
trails = []
for r in REGIONS:
    _, d, _ = run("W6", ["cloudtrail", "describe-trails", "--include-shadow-trails"], r)
    trails += (d or {}).get("trailList", [])
if not trails: find("W6", "account", f"No CloudTrail trail in any audited region ({len(REGIONS)})", "P1")
for t in {t["TrailARN"]: t for t in trails}.values():
    if not t.get("IsMultiRegionTrail"): find("W29", t["Name"], f"Trail {t['Name']} is single-region", "P1")
    if not t.get("LogFileValidationEnabled"): find("NEW-TRAIL-VALIDATION", t["Name"], f"Trail {t['Name']} log file validation off", "P2")
gd = cfg = aa = 0
for r in REGIONS:
    _, d, _ = run("W8", ["guardduty", "list-detectors"], r); gd += len((d or {}).get("DetectorIds", []))
    _, d, _ = run("W8", ["configservice", "describe-configuration-recorder-status"], r); cfg += sum(1 for x in (d or {}).get("ConfigurationRecordersStatus", []) if x.get("recording"))
    _, d, _ = run("NEW-ACCESS-ANALYZER", ["accessanalyzer", "list-analyzers"], r); aa += len((d or {}).get("analyzers", []))
if not gd: find("W8", "account", "GuardDuty: no detector in any audited region", "P2")
if not cfg: find("W8", "account", "AWS Config: no recording recorder in any audited region", "P2")
if not aa: find("NEW-ACCESS-ANALYZER", "account", "IAM Access Analyzer: no analyzer in any audited region", "P3")
rc, d, e = run("W7", ["budgets", "describe-budgets", "--account-id", ACCT])
# describe-budgets prints NOTHING (rc=0, empty stdout) when the account has no budgets
if rc == 0 and not (d.get("Budgets") if isinstance(d, dict) else None): find("W7", "account", "No AWS Budgets: a leaked key's spend is only noticed on the invoice", "P1")
CE_OFF = "not enabled for cost explorer"
rc, d, e = run("W23", ["ce", "get-anomaly-monitors"], ok_errors=(CE_OFF,))
if rc == 0 and not (d or {}).get("AnomalyMonitors"):
    rc2, d2, _ = run("W23", ["ce", "get-anomaly-subscriptions"])
    find("W23", "account", f"No Cost Anomaly Detection monitor (subscriptions: {len((d2 or {}).get('AnomalySubscriptions', []))})", "P2")
elif rc != 0 and CE_OFF in e.lower():
    find("W23", "account", "Cost Explorer was never enabled, so no Cost Anomaly Detection monitor can exist", "P2", evidence=e.splitlines()[-1][:200])
bl = 0
for r in REGIONS:
    rc, d, e = run("NEW-BEDROCK-LOGGING", ["bedrock", "get-model-invocation-logging-configuration"], r)
    bl += 1 if (d or {}).get("loggingConfig") else 0
if not bl: find("NEW-BEDROCK-LOGGING", "account", "Bedrock model invocation logging off in every audited region (LLMjacking invisible)", "P2")
rc, d, e = run("NEW-BACKUP-VAULT-LOCK", ["backup", "list-backup-vaults"], HOME)
if rc == 0 and not any(v.get("Locked") for v in d.get("BackupVaultList", [])): find("NEW-BACKUP-VAULT-LOCK", "account", "No AWS Backup vault with Vault Lock", "P2")

# ================= EC2 / network (per region) =================
ADMIN_PORTS = set(overlay.param("W2.admin_ports", [22, 3389, 3306, 5432, 6379, 9200, 27017, 2375, 5601, 8080]))
for r in REGIONS:
    _, sgs, _ = run("W2", ["ec2", "describe-security-groups"], r)
    _, enis, _ = run("W2", ["ec2", "describe-network-interfaces"], r)
    pub_sg = {g["GroupId"] for n in (enis or {}).get("NetworkInterfaces", []) if n.get("Association", {}).get("PublicIp") for g in n.get("Groups", [])}
    for g in (sgs or {}).get("SecurityGroups", []):
        allt, admin = [], []
        for p in g.get("IpPermissions", []):
            world = [x["CidrIp"] for x in p.get("IpRanges", []) if x["CidrIp"] == "0.0.0.0/0"] + [x["CidrIpv6"] for x in p.get("Ipv6Ranges", []) if x["CidrIpv6"] == "::/0"]
            if not world: continue
            if p["IpProtocol"] == "-1": allt += world
            elif p["IpProtocol"] in ("tcp", "6"):
                ports = [x for x in ADMIN_PORTS if p.get("FromPort", 0) <= x <= p.get("ToPort", 65535)]
                if ports: admin.append(f"{ports} from {world}")
        attached = g["GroupId"] in pub_sg
        stt, sev = ("confirmed", "P1") if attached else ("needs_validation", None)
        if admin: find("W2", g["GroupName"], f"SG {g['GroupName']} ({r}) admin ports open to the world: {admin}; {'attached to public ENI' if attached else 'not on a public ENI'}", sev, stt)
        if allt: find("W2", g["GroupName"], f"SG {g['GroupName']} ({r}) ALL traffic (proto -1) from {allt}; {'attached to public ENI' if attached else 'not on a public ENI'}", sev, stt)
    _, inst, _ = run("W15", ["ec2", "describe-instances"], r)
    for res in (inst or {}).get("Reservations", []):
        for i in res["Instances"]:
            if i["State"]["Name"] == "terminated": continue
            nm = tagname(i.get("Tags"), i["InstanceId"])
            if i.get("MetadataOptions", {}).get("HttpTokens") == "optional":
                find("W15", nm, f"Instance {nm} ({r}) allows IMDSv1, hop limit {i['MetadataOptions'].get('HttpPutResponseHopLimit')}, profile {i.get('IamInstanceProfile', {}).get('Arn', '-').split('/')[-1]}", "P1")
    _, lts, _ = run("NEW-IMDS-LAUNCH-TEMPLATE", ["ec2", "describe-launch-templates"], r)
    for lt in (lts or {}).get("LaunchTemplates", []):
        _, v, _ = run("NEW-IMDS-LAUNCH-TEMPLATE", ["ec2", "describe-launch-template-versions", "--launch-template-id", lt["LaunchTemplateId"], "--versions", "$Latest"], r)
        for ver in (v or {}).get("LaunchTemplateVersions", []):
            data = ver["LaunchTemplateData"]
            if (data.get("MetadataOptions") or {}).get("HttpTokens", "optional") != "required":
                find("NEW-IMDS-LAUNCH-TEMPLATE", lt["LaunchTemplateName"], f"Launch template {lt['LaunchTemplateName']} ({r}) does not require IMDSv2", "P2")
            if data.get("UserData"):
                txt = base64.b64decode(data["UserData"]).decode(errors="ignore")
                names = sorted(set(m.group(1) for m in re.finditer(r"\b([A-Z][A-Z0-9_]{2,})\s*=", txt) if SECRET_RE.search(m.group(1))))
                if names: find("NEW-USERDATA-SECRETS", lt["LaunchTemplateName"], f"Launch template {lt['LaunchTemplateName']} user-data assigns secret-named vars {names} (values not shown)", "P2")
    for res in (inst or {}).get("Reservations", []):
        for i in res["Instances"]:
            if i["State"]["Name"] == "terminated": continue
            nm = tagname(i.get("Tags"), i["InstanceId"])
            rc, ud, e = run("NEW-USERDATA-SECRETS", ["ec2", "describe-instance-attribute", "--instance-id", i["InstanceId"], "--attribute", "userData"], r)
            val = ((ud or {}).get("UserData") or {}).get("Value")
            if val:
                txt = base64.b64decode(val).decode(errors="ignore")
                names = sorted(set(m.group(1) for m in re.finditer(r"\b([A-Z][A-Z0-9_]{2,})\s*=", txt) if SECRET_RE.search(m.group(1))))
                if names: find("NEW-USERDATA-SECRETS", nm, f"Instance {nm} user-data assigns secret-named vars {names}", "P2")
    _, md, _ = run("NEW-IMDS-ACCOUNT-DEFAULT", ["ec2", "get-instance-metadata-defaults"], r)
    if (md or {}).get("AccountLevel", {}).get("HttpTokens") != "required": find("NEW-IMDS-ACCOUNT-DEFAULT", "account", f"Account IMDS default does not require IMDSv2 ({r})", "P3")
    _, d, _ = run("W32", ["ec2", "get-ebs-encryption-by-default"], r)
    if d and d.get("EbsEncryptionByDefault") is False: find("W32", "account", f"EBS default encryption off ({r})", "P2")
    _, d, _ = run("NEW-SNAPSHOT-BPA", ["ec2", "get-snapshot-block-public-access-state"], r)
    _, d2, _ = run("NEW-SNAPSHOT-BPA", ["ec2", "get-image-block-public-access-state"], r)
    if (d or {}).get("State") == "unblocked" or (d2 or {}).get("ImageBlockPublicAccessState") == "unblocked":
        find("NEW-SNAPSHOT-BPA", "account", f"Snapshot/AMI Block Public Access off ({r})", "P3")
    _, d, _ = run("NEW-ALLOWED-AMIS", ["ec2", "get-allowed-images-settings"], r)
    if (d or {}).get("State") in (None, "disabled"): find("NEW-ALLOWED-AMIS", "account", f"Allowed AMIs not enforced ({r}) - whoAMI exposure", "P3")
    _, sn, _ = run("W34", ["ec2", "describe-snapshots", "--owner-ids", "self"], r)
    for s in (sn or {}).get("Snapshots", []):
        nm = tagname(s.get("Tags"), s["SnapshotId"])
        if not s["Encrypted"]: find("NEW-UNENCRYPTED-SNAPSHOT", nm, f"Snapshot {nm} ({r}) unencrypted", "P2")
        _, at, _ = run("W34", ["ec2", "describe-snapshot-attribute", "--snapshot-id", s["SnapshotId"], "--attribute", "createVolumePermission"], r)
        perms = (at or {}).get("CreateVolumePermissions", [])
        if perms: find("W34", nm, f"Snapshot {nm} shared {perms}", "P0" if any(p.get("Group") == "all" for p in perms) else "P1")
    _, ims, _ = run("W19", ["ec2", "describe-images", "--owners", "self"], r)
    for im in (ims or {}).get("Images", []):
        if im.get("Public"): find("NEW-PUBLIC-AMI", im["Name"], f"AMI {im['Name']} is public", "P0")
        if age_days(im["CreationDate"]) > 365: find("W19", im["Name"], "AMI older than 12 months", "P2")
    _, rs, _ = run("W34", ["rds", "describe-db-snapshots"], r)
    for s in (rs or {}).get("DBSnapshots", []):
        _, a, _ = run("W34", ["rds", "describe-db-snapshot-attributes", "--db-snapshot-identifier", s["DBSnapshotIdentifier"]], r)
        if "all" in json.dumps(a or {}): find("W34", s["DBSnapshotIdentifier"], "RDS snapshot public", "P0")
    _, vpce, _ = run("W14", ["ec2", "describe-vpc-endpoints"], r)
    _, kp, _ = run("W12", ["ec2", "describe-key-pairs"], r)

# ================= compute / app services (per region) =================
RT_DEPRECATED = re.compile(r"^(nodejs(1[0-8]|[0-9])\.x|python3\.[0-9]$|python2\.7|ruby2\.7|java8$|dotnet(core)?[0-6](\.\d)?$|go1\.x|provided$)")
for r in REGIONS:
    _, fl, _ = run("W17", ["lambda", "list-functions"], r)
    for f in (fl or {}).get("Functions", []):
        fn = f["FunctionName"]
        if f.get("Runtime") and RT_DEPRECATED.match(f["Runtime"]): find("W17", fn, f"Lambda {fn} deprecated runtime {f['Runtime']}", "P2")
        names = sorted(k for k in ((f.get("Environment") or {}).get("Variables") or {}) if SECRET_RE.search(k))
        if names: find("NEW-LAMBDA-ENV-SECRETS", fn, f"Lambda {fn} ({r}) plaintext env vars named {names} (values not shown)", "P1")
        envobj = f.get("Environment") or {}
        if not names and envobj.get("Error"):
            find("NEW-LAMBDA-ENV-SECRETS", fn, f"Lambda {fn} ({r}) has environment variables the audit role cannot list (KMS decrypt denied by design): names unverified", None, "needs_validation")
        rc, p, e = run("NEW-LAMBDA-PUBLIC-POLICY", ["lambda", "get-policy", "--function-name", fn], r, ok_errors=("ResourceNotFound",))
        if rc == 0:
            for s in stmts(json.loads(p["Policy"])):
                c = json.dumps(s.get("Condition", {}))
                if star_principal(s.get("Principal")) and "SourceArn" not in c and "SourceAccount" not in c and "PrincipalOrgID" not in c:
                    find("NEW-LAMBDA-PUBLIC-POLICY", fn, f"Lambda {fn} resource policy: Principal * {s.get('Action')} without source condition", "P1")
        rc, u, e = run("W43", ["lambda", "list-function-url-configs", "--function-name", fn], r)
        for c in (u or {}).get("FunctionUrlConfigs", []):
            if c["AuthType"] == "NONE": find("W43", fn, f"Lambda {fn} Function URL AuthType NONE", "P1")
    _, apis, _ = run("NEW-APIGW-NO-AUTH", ["apigatewayv2", "get-apis"], r)
    for api in (apis or {}).get("Items", []):
        _, rt, _ = run("NEW-APIGW-NO-AUTH", ["apigatewayv2", "get-routes", "--api-id", api["ApiId"]], r)
        bad = [x["RouteKey"] for x in (rt or {}).get("Items", []) if x.get("AuthorizationType", "NONE") == "NONE" and re.search(r"admin|refund|internal|delete|debug|payment", x["RouteKey"], re.I)]
        if bad: find("NEW-APIGW-NO-AUTH", api["Name"], f"API {api['Name']} ({r}) privileged-looking routes with no auth: {bad}", "P2")
    _, rest, _ = run("NEW-APIGW-NO-AUTH", ["apigateway", "get-rest-apis"], r)
    _, tds, _ = run("W35", ["ecs", "list-task-definitions", "--status", "ACTIVE"], r)
    seen = set()
    for arn in reversed((tds or {}).get("taskDefinitionArns", [])):
        fam = arn.split("/")[-1].split(":")[0]
        if fam in seen: continue
        seen.add(fam)
        _, t, _ = run("W35", ["ecs", "describe-task-definition", "--task-definition", arn], r)
        td = (t or {}).get("taskDefinition", {})
        for c in td.get("containerDefinitions", []):
            names = sorted(e["name"] for e in c.get("environment", []) if SECRET_RE.search(e["name"]))
            if names: find("NEW-ECS-ENV-SECRETS", fam, f"ECS task {fam} container {c['name']} plaintext env {names} (use secrets:)", "P1")
            if c.get("privileged"): find("W35", fam, f"ECS task {fam} privileged container", "P1")
            if td.get("networkMode") == "host" or any(p.get("hostPort") for p in c.get("portMappings", [])):
                find("W35", fam, f"ECS task {fam} exposes host ports", "P2", "needs_validation")
    _, cls, _ = run("W35", ["ecs", "list-clusters"], r)
    for c in (cls or {}).get("clusterArns", []):
        _, sv, _ = run("W35", ["ecs", "list-services", "--cluster", c], r)
        arns = (sv or {}).get("serviceArns", [])
        for i in range(0, len(arns), 10):
            run("W35", ["ecs", "describe-services", "--cluster", c, "--services"] + arns[i:i+10], r)
    _, cb, _ = run("NEW-CODEBUILD", ["codebuild", "list-projects"], r)
    pj = (cb or {}).get("projects", [])
    for i in range(0, len(pj), 100):
        _, bp, _ = run("NEW-CODEBUILD", ["codebuild", "batch-get-projects", "--names"] + pj[i:i+100], r)
        for p in (bp or {}).get("projects", []):
            env = p.get("environment", {})
            names = sorted(v["name"] for v in env.get("environmentVariables", []) if v.get("type", "PLAINTEXT") == "PLAINTEXT" and SECRET_RE.search(v["name"]))
            if env.get("privilegedMode") or names:
                find("NEW-CODEBUILD", p["name"], f"CodeBuild {p['name']} ({r}) privileged={env.get('privilegedMode')} plaintext secret-named env {names}", "P1")
            for grp in (p.get("webhook") or {}).get("filterGroups", []):
                for fl_ in grp:
                    if fl_["type"] == "ACTOR_ACCOUNT_ID" and not (fl_["pattern"].startswith("^") and fl_["pattern"].endswith("$")):
                        find("NEW-CODEBUILD-WEBHOOK", p["name"], f"CodeBuild {p['name']} webhook ACTOR_ACCOUNT_ID filter unanchored", "P1")
    _, ps, _ = run("NEW-SSM-PLAINTEXT", ["ssm", "describe-parameters"], r)
    for p in (ps or {}).get("Parameters", []):
        if p["Type"] == "String" and SECRET_RE.search(p["Name"]): find("NEW-SSM-PLAINTEXT", p["Name"], f"SSM parameter {p['Name']} ({r}) is String, not SecureString", "P2")
    _, ss, _ = run("W37", ["secretsmanager", "list-secrets"], r)
    for s in (ss or {}).get("SecretList", []):
        if not s.get("RotationEnabled"): find("W37", s["Name"], f"Secret {s['Name']} rotation disabled", "P3")
        rc, rp, e = run("W26", ["secretsmanager", "get-resource-policy", "--secret-id", s["ARN"]], r)
        for a in re.findall(r"arn:aws:iam::(\d{12})", (rp or {}).get("ResourcePolicy") or ""):
            if a != ACCT: find("W26", s["Name"], "Secret resource policy grants another account", "P1")
    _, rp, _ = run("W30", ["ecr", "describe-repositories"], r)
    for rep in (rp or {}).get("repositories", []):
        n = rep["repositoryName"]
        if rep.get("imageTagMutability") == "MUTABLE" and not rep.get("imageScanningConfiguration", {}).get("scanOnPush"):
            find("NEW-ECR-HYGIENE", n, f"ECR {n} ({r}) mutable tags and no scan-on-push", "P3")
        rc, pol, e = run("W30", ["ecr", "get-repository-policy", "--repository-name", n], r, ok_errors=("RepositoryPolicyNotFound",))
        if rc == 0 and any(star_principal(s.get("Principal")) for s in stmts(json.loads(pol["policyText"]))): find("W30", n, f"ECR {n} policy Principal *", "P1")
    _, tp, _ = run("W44", ["sns", "list-topics"], r)
    for t in (tp or {}).get("Topics", []):
        _, a, _ = run("W44", ["sns", "get-topic-attributes", "--topic-arn", t["TopicArn"]], r)
        for s in stmts(json.loads((a or {}).get("Attributes", {}).get("Policy", "{}"))):
            if s.get("Effect") == "Allow" and star_principal(s.get("Principal")) and not s.get("Condition"):
                find("W44", t["TopicArn"].split(":")[-1], f"SNS {t['TopicArn'].split(':')[-1]} Principal * {s.get('Action')} no condition", "P2"); break
    _, q, _ = run("W44", ["sqs", "list-queues"], r)
    for u in (q or {}).get("QueueUrls", []):
        _, a, _ = run("W44", ["sqs", "get-queue-attributes", "--queue-url", u, "--attribute-names", "Policy"], r)
        for s in stmts(json.loads((a or {}).get("Attributes", {}).get("Policy", "{}"))):
            if s.get("Effect") == "Allow" and star_principal(s.get("Principal")) and not s.get("Condition"):
                find("W44", u.split("/")[-1], f"SQS {u.split('/')[-1]} Principal * {s.get('Action')} no condition", "P2"); break
    _, lg, _ = run("W45", ["logs", "describe-log-groups"], r)
    for g in (lg or {}).get("logGroups", []):
        if g.get("retentionInDays") is None: find("W45", g["logGroupName"], f"Log group {g['logGroupName']} ({r}) never expires", "P3")
    _, ks, _ = run("W26", ["kms", "list-aliases"], r)
    alias = {}
    for a in (ks or {}).get("Aliases", []):
        if a.get("TargetKeyId") and not a["AliasName"].startswith("alias/aws/"): alias.setdefault(a["TargetKeyId"], a["AliasName"])
    for kid, an in alias.items():
        _, km, _ = run("NEW-KMS-PENDING-DELETION", ["kms", "describe-key", "--key-id", kid], r)
        meta = (km or {}).get("KeyMetadata", {})
        if meta.get("KeyState") == "PendingDeletion": find("NEW-KMS-PENDING-DELETION", an, f"KMS {an} ({r}) PendingDeletion on {str(meta.get('DeletionDate'))[:10]}", "P2"); continue
        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled": continue
        _, rot, _ = run("NEW-KMS-ROTATION", ["kms", "get-key-rotation-status", "--key-id", kid], r)
        if rot and not rot.get("KeyRotationEnabled") and meta.get("KeySpec") == "SYMMETRIC_DEFAULT": find("NEW-KMS-ROTATION", an, f"KMS {an} ({r}) rotation off", "P3")
        rc, kp, e = run("W26", ["kms", "get-key-policy", "--key-id", kid], r)
        if rc == 0:
            for a in re.findall(r"arn:aws:iam::(\d{12})", kp["Policy"]):
                if a != ACCT: find("W26", an, "KMS key policy grants another account", "P1"); break
    _, ses, _ = run("W36", ["sesv2", "get-account"], r)
    _, sid, _ = run("W36", ["sesv2", "list-email-identities"], r)
    for i in (sid or {}).get("EmailIdentities", []):
        prod = (ses or {}).get("ProductionAccessEnabled")
        find("W36", i["IdentityName"], f"SES identity {i['IdentityName']} ({r}); production access={prod}", "P2" if prod else "P3", "confirmed" if prod else "needs_validation")

# ================= data stores / clusters =================
PG_EOL = {"11": "2023-11", "12": "2024-11", "13": "2025-11", "14": "2026-11", "15": "2027-11"}
for r in REGIONS:
    _, dbs, _ = run("NEW-RDS-EXPOSURE", ["rds", "describe-db-instances"], r)
    for db in (dbs or {}).get("DBInstances", []):
        n = db["DBInstanceIdentifier"]; issues = []
        if db.get("PubliclyAccessible"): issues.append("publicly accessible")
        if not db.get("StorageEncrypted"): issues.append("unencrypted")
        if db.get("BackupRetentionPeriod", 0) == 0: issues.append("no backups")
        if not db.get("DeletionProtection"): issues.append("no deletion protection")
        if issues: find("NEW-RDS-EXPOSURE", n, f"RDS {n} ({r}): {', '.join(issues)}", "P1" if db.get("PubliclyAccessible") or db.get("BackupRetentionPeriod", 0) == 0 else "P2")
        major = db["EngineVersion"].split(".")[0]
        if db["Engine"] == "postgres" and PG_EOL.get(major, "9999") <= (NOW + datetime.timedelta(days=180)).strftime("%Y-%m"):
            find("W20", n, f"RDS {n} runs postgres {db['EngineVersion']}: community EOL {PG_EOL[major]} (within 6 months)", "P2")
    _, cl, _ = run("W9", ["eks", "list-clusters"], r)
    for c in (cl or {}).get("clusters", []):
        _, d, _ = run("W9", ["eks", "describe-cluster", "--name", c], r)
        cc = (d or {}).get("cluster", {}); vpc = cc.get("resourcesVpcConfig", {})
        if vpc.get("endpointPublicAccess") and "0.0.0.0/0" in vpc.get("publicAccessCidrs", []): find("W9", c, f"EKS {c} ({r}) public API endpoint open to 0.0.0.0/0", "P1")
        ac = cc.get("accessConfig", {})
        if ac.get("bootstrapClusterCreatorAdminPermissions") or "CONFIG_MAP" in ac.get("authenticationMode", ""):
            find("NEW-EKS-AUTH", c, f"EKS {c}: creator-admin bootstrap={ac.get('bootstrapClusterCreatorAdminPermissions')} authMode={ac.get('authenticationMode')} (invisible standing admin)", "P2")
        _, ae, _ = run("NEW-EKS-AUTH", ["eks", "list-access-entries", "--cluster-name", c], r)
        for pa in (ae or {}).get("accessEntries", []):
            if ":role/aws-service-role/" in pa or "AWSServiceRole" in pa: continue
            _, ap, _ = run("NEW-EKS-AUTH", ["eks", "list-associated-access-policies", "--cluster-name", c, "--principal-arn", pa], r)
            for x in (ap or {}).get("associatedAccessPolicies", []):
                if x["policyArn"].endswith("AmazonEKSClusterAdminPolicy") and x["accessScope"]["type"] == "cluster" and ":user/" in pa:
                    find("NEW-EKS-AUTH", c, f"EKS {c}: IAM user {pa.split('/')[-1]} has ClusterAdmin at cluster scope", "P1")
        STATE_EKS = (c, cc.get("version"))
    # Cognito
    _, up, _ = run("NEW-COGNITO-SIGNUP", ["cognito-idp", "list-user-pools", "--max-results", "60"], r)
    for p in (up or {}).get("UserPools", []):
        _, dp, _ = run("NEW-COGNITO-SIGNUP", ["cognito-idp", "describe-user-pool", "--user-pool-id", p["Id"], "--query", "UserPool.{a:AdminCreateUserConfig,m:MfaConfiguration}"], r)
        if dp and not dp["a"].get("AllowAdminCreateUserOnly"): find("NEW-COGNITO-SIGNUP", p["Name"], f"Cognito pool {p['Name']} ({r}) allows public self sign-up", "P2")
        _, cls_, _ = run("NEW-COGNITO-ATTR", ["cognito-idp", "list-user-pool-clients", "--user-pool-id", p["Id"]], r)
        for c in (cls_ or {}).get("UserPoolClients", []):
            _, w, _ = run("NEW-COGNITO-ATTR", ["cognito-idp", "describe-user-pool-client", "--user-pool-id", p["Id"], "--client-id", c["ClientId"], "--query", "UserPoolClient.WriteAttributes"], r)
            risky = [a for a in (w or []) if a == "email" or a.startswith("custom:")]
            if risky: find("NEW-COGNITO-ATTR", c["ClientName"], f"Cognito client {c['ClientName']} lets users write {risky}", "P1")
    _, ip, _ = run("NEW-COGNITO-UNAUTH", ["cognito-identity", "list-identity-pools", "--max-results", "60"], r)
    for p in (ip or {}).get("IdentityPools", []):
        _, d, _ = run("NEW-COGNITO-UNAUTH", ["cognito-identity", "describe-identity-pool", "--identity-pool-id", p["IdentityPoolId"]], r)
        if not (d or {}).get("AllowUnauthenticatedIdentities"): continue
        _, rl, _ = run("NEW-COGNITO-UNAUTH", ["cognito-identity", "get-identity-pool-roles", "--identity-pool-id", p["IdentityPoolId"]], r)
        un = (rl or {}).get("Roles", {}).get("unauthenticated")
        perms = []
        if un:
            rn = un.split("/")[-1]
            ent = next((x for x in auth.get("RoleDetailList", []) if x["RoleName"] == rn), {})
            for pn, doc in entity_docs(ent, "RolePolicyList"):
                for s in stmts(doc):
                    if s.get("Effect") == "Allow" and any(a.endswith(":*") or a == "*" for a in aslist(s.get("Action"))): perms.append(f"{pn}:{aslist(s.get('Action'))} on {aslist(s.get('Resource'))}")
        find("NEW-COGNITO-UNAUTH", p["IdentityPoolName"], f"Identity pool {p['IdentityPoolName']} allows unauthenticated identities; unauth role {un.split('/')[-1] if un else '-'} grants {perms or 'n/a'}", "P0" if perms else "P2")

# ================= DNS (global) =================
_, hz, _ = run("NEW-DANGLING-DNS", ["route53", "list-hosted-zones"])
for z in (hz or {}).get("HostedZones", []):
    _, rr, _ = run("NEW-DANGLING-DNS", ["route53", "list-resource-record-sets", "--hosted-zone-id", z["Id"].split("/")[-1]])
    for rec in (rr or {}).get("ResourceRecordSets", []):
        if rec["Type"] != "CNAME": continue
        tgt = rec["ResourceRecords"][0]["Value"].rstrip(".")
        name = rec["Name"].rstrip(".")
        m = re.match(r"(.+)\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com$", tgt) or re.match(r"(.+)\.s3[.-]?([a-z0-9-]*)\.amazonaws\.com$", tgt)
        if m:
            rc, d, e = run("NEW-DANGLING-DNS", ["s3api", "head-bucket", "--bucket", m.group(1)], ok_errors=("404", "Not Found", "403"))
            if rc != 0 and ("404" in e or "Not Found" in e): find("NEW-DANGLING-DNS", name, f"{name} CNAME -> S3 bucket {m.group(1)} that does not exist (claimable)", "P1")
        m = re.match(r"(.+)\.([a-z0-9-]+)\.elasticbeanstalk\.com$", tgt)
        if m:
            rc, d, e = run("NEW-DANGLING-DNS", ["elasticbeanstalk", "check-dns-availability", "--cname-prefix", m.group(1)], m.group(2), ok_errors=("AccessDenied",))
            avail = (d or {}).get("Available")
            if rc != 0:  # permission gap fallback: public DNS lookup (NXDOMAIN = nobody owns the EB name)
                p = subprocess.run(["python3", "-c", f"import socket;socket.gethostbyname('{tgt}')"], capture_output=True)
                avail = p.returncode != 0
            if avail: find("NEW-DANGLING-DNS", name, f"{name} CNAME -> Elastic Beanstalk name {m.group(1)} that anyone can register", "P1")
        if re.search(r"cloudfront\.net$|azurewebsites\.net$|herokuapp\.com$|github\.io$", tgt):
            p = subprocess.run(["python3", "-c", f"import socket;socket.gethostbyname('{tgt}')"], capture_output=True)
            if p.returncode != 0: find("NEW-DANGLING-DNS", name, f"{name} CNAME -> {tgt} does not resolve", "P1", "needs_validation")

# Not run in this pass: W13 (needs deploy history), W16 (no org), W21 ACM (no certs), W22 (Cost Explorer opt-in), W39 (needs public URLs), W42 (no ALB)
for r in REGIONS:
    run("W21", ["acm", "list-certificates"], r); run("W42", ["elbv2", "describe-load-balancers"], r)
json.dump({"findings": F, "errors": ERR, "permission_gaps": sorted(set(map(tuple, GAPS))), "regions": REGIONS, "runtime_s": round(time.time() - T0)},
          open(os.environ.get("AUDIT_FINDINGS_OUT", os.path.join(HERE, "v3_raw.json")), "w"), indent=1, default=str)
print(len(F), "findings;", len(ERR), "errors;", round(time.time() - T0), "s")
for e in ERR: print("ERR", e)
