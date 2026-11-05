# roqy vuln-lab — מעבדה פגיעה בכוונה ל-AWS

> ⚠️ **רק בחשבון AWS SANDBOX ריק וייעודי. אף פעם לא בפרודקשן, לא בחשבון של לקוח ולא בחשבון של roqy.**
> ה-Terraform נועל את עצמו לחשבון אחד (`allowed_account_ids`). אם תריץ אותו עם פרופיל של חשבון אחר, הוא ייכשל לפני שיגע במשהו.

## מה זה
סביבת Terraform ששותלת בכוונה **חולשה אחת מתויגת לכל סוג פריצה** שראינו ב-AWS בשנים האחרונות (18 הקטגוריות מעמוד "מפת הפריצות"). החולשות מסודרות מהקטנות (log group בלי retention) ועד הגדולות (role שכל רפו ב-GitHub יכול להתחבר אליו). כל משאב מתויג `roqy-lab=true` ו-`roqy-plant=<id>`.

אחרי ההקמה מריצים את roqy-audit (Hermes harness) עם גישה read-only, ומשווים את הדוח מול `EXPECTED-FINDINGS.yaml` בעזרת `scripts/score.py`. כל plant שלא נתפס הוא באג בכיסוי, וממנו בונים את ה-regression test.

| קובץ | מה יש בו |
|---|---|
| `terraform/` | המעבדה עצמה: אזור ראשי `eu-central-1` ומודול קטן ב-`us-east-1` שבודק שהאודיט עובר על כל האזורים |
| `access/` | ה-role לקריאה בלבד (תואם ל-`cloudformation/audit-role.yaml`) והמשתמש `roqy-auditor-bot` |
| `EXPECTED-FINDINGS.yaml` | ה-ground truth: לכל plant יש קטגוריה, check ID צפוי (W-xx או NEW-xx שעוד חסר), חומרה, פקודת זיהוי read-only ומצב ברירת מחדל (פעיל או כבוי) |
| `scripts/score.py` | ניקוד של findings.json או של דוח markdown מול ה-YAML |
| `scripts/validate_commands.py` | מוודא שכל פקודת `aws` ב-YAML קיימת באמת ב-AWS CLI. הוא היה תופס את `get-anomaly-detectors` ואת `list-invocations` |
| `scripts/gen_expected.py` | המקור של ה-YAML. עורכים כאן ומריצים מחדש |
| `iac-samples/` | דוגמת whoAMI לבדיקת האודיט על הרפו |

## אזהרות — לקרוא לפני apply
1. **אין סודות אמיתיים.** כל ערך שנראה כמו סוד (`AKIAFAKE...`, `sk_live_FAKE...`, `ghp_FAKE...`) הוא מזויף.
2. **`allow_public=false` (ברירת המחדל):** שום דבר לא חשוף באמת לאינטרנט, חוץ מכמה endpoints שמתועדים ולא מזיקים:
   - Route ב-API Gateway שמחזיר "hello", עם throttling של בקשה אחת לשנייה
   - Lambda policy עם `Principal *` על אותה פונקציה לא מזיקה
   - SNS ו-SQS עם `Principal *`, בלי subscribers ועם retention של 60 שניות
3. **`allow_public=true`:** הופך לציבוריים באמת את המשאבים האלה:
   - bucket policy שמאפשרת קריאה וכתיבה לכל העולם
   - snapshot ו-AMI
   - Lambda Function URL בלי auth
   - ECR pull
   - trust policy עם `Principal "*"`

   מפעילים את זה רק לריצה קצרה ובהשגחה, ומיד אחריה מחזירים עם `terraform apply -var allow_public=false`.
   **ה-Block Public Access ברמת החשבון לא משתנה אף פעם.** אם הוא פעיל, ה-apply של ה-bucket הציבורי ייכשל עם AccessDenied, וזה תקין ובטוח. אותו דבר עם Snapshot/Image Block Public Access.
4. **Guard:** לכל principal שאפשר להגיע אליו מבחוץ מוצמד permissions boundary בשם `roqy-lab-guard-deny-all` שחוסם הכול. זה חל על role ה-GitHub OIDC, על ה-role ה-cross-account, על משתמש הקונסול ועל ה-role של Cognito unauth. גם אם מישהו ינסה את החולשה, הוא יקבל session ריק. מדיניות ההרשאות וה-trust עדיין גלויות לאודיט, **והאודיט חייב לדווח עליהן** (ב-YAML הן מסומנות `guarded_by_boundary: true`). משתמש ה-privesc (`roqy-lab-intern`) קיבל במכוון אפס credentials.
5. **ברירת המחדל כוללת עכשיו משאבים רצים**, כי יש קרדיטים:
   - מכונת EC2 (`instance_state=running`) עם IMDSv1, IP ציבורי, SG פתוח ו-role של `Action:*`. אין לה key pair ולא רץ עליה שום שירות, אבל היא עדיין מטרה. לא משאירים אותה פתוחה שבועות.
   - RDS PostgreSQL 14 על `db.t4g.micro`, עם `publicly_accessible=true`, בלי הצפנה, בלי גיבוי, בלי deletion protection ובלי final snapshot. ה-SG פתוח רק ל-VPC, אלא אם `allow_public=true`.
   - EKS עם endpoint ציבורי `0.0.0.0/0`, עם `bootstrapClusterCreatorAdminPermissions=true`, ועם access entry שנותן cluster-admin למשתמש `roqy-lab-intern`. זה המשתמש עם ה-privesc, ואין לו credentials. עוד חלק מה-EKS: node אחד `t4g.small` ב-subnet ציבורי, **בלי NAT gateway**.
   - ה-GitHub OIDC role **לא** ממופה ל-EKS בכוונה. ה-boundary לא חוסם אימות ל-EKS, ולכן מיפוי כזה היה פותח את הקלאסטר לכל רפו ב-GitHub.
6. **למה `allow_public` נשאר `false` גם עם קרדיטים:** חשיפה אמיתית לאינטרנט מושכת סורקים אוטומטיים ו-cryptojacking תוך שעות, והקרדיטים לא מגינים מזה. בוט כורה ייראה בדיוק כמו "ממצא". הדרך הנכונה להפעיל את זה:
   ```bash
   terraform apply -var allow_public=true     # short supervised window only
   # run the audit now
   terraform apply -var allow_public=false    # immediately after
   ```

## הערכת עלות חודשית (eu-central-1, הערכה גסה, נובמבר 2026)
| רכיב | ברירת מחדל | בערך לחודש |
|---|---|---|
| EKS control plane (standard support) | פעיל | 73$ |
| EKS node `t4g.small`, 20GB gp2, IPv4 ציבורי | פעיל | 20$ |
| RDS `db.t4g.micro`, 20GB, IPv4 ציבורי | פעיל | 18$ |
| EC2 `t4g.nano`, 8GB, IPv4 ציבורי | פעיל | 7$ |
| KMS (key אחד פעיל), Route53 private zone, volume ו-snapshot של 1GB | פעיל | 2$ |
| Lambda, API GW, SNS, SQS, Cognito, ECR, SSM, IAM, CodeBuild (לא רץ) | פעיל | פחות מ-1$ |
| **סה"כ ברירת מחדל** | | **בערך 120$ לחודש (בערך 4$ ליום)** |
| `eks_version` ישן (plant של eks-old-version), extended support | כבוי | עוד 365$ |
| `rds_engine_version=13` (Extended Support) | כבוי | עוד 45$ בערך |
| `create_weak_trail=true` | כבוי | פחות מ-1$ |
| `enable_secrets_manager=true` | כבוי | 0.4$ |

עם `instance_state=stopped`, `enable_eks=false` ו-`enable_rds=false` יורדים לבערך 3$ לחודש. **הכי זול: להריץ את האודיט ולפרק באותו יום.** ההקמה לוקחת בערך 20 דקות, בגלל EKS.

## דרישות
- Terraform 1.6 ומעלה
- AWS CLI v2 עדכני. משאבים שה-provider עוד לא תומך בהם מוגדרים דרך local-exec, ו-SSE-C דורש CLI שמכיר את `BlockedEncryptionTypes`. בודקים עם `aws --version` ומעדכנים אם צריך.
- Python 3 עם `pyyaml`, בשביל score.py

## שלב 1 — פרופיל admin לחשבון ה-sandbox
מחשבון ה-admin של ה-sandbox (SSO או משתמש זמני):
```bash
aws configure --profile roqy-sandbox-admin        # or: aws configure sso --profile roqy-sandbox-admin
aws sts get-caller-identity --profile roqy-sandbox-admin   # verify: this MUST be the sandbox account id
```

## שלב 2 — הקמת המעבדה
```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
# edit: sandbox_account_id = "<12 digits>"   (optional: foreign_account_id = a 2nd account you own)
terraform init
terraform plan -out lab.plan
terraform apply lab.plan        # ~20 min (EKS)
terraform output lab_summary
```
אופציות:
- `-var foreign_account_id=<חשבון שני שלך>` מפעיל plants אמיתיים של cross-account: KMS, S3, snapshot share ו-trust.
- `-var create_weak_trail=true` מחליף את "אין CloudTrail" ב-trail חלש.
- `-var enable_rds=false` / `-var enable_eks=false` / `-var instance_state=stopped` מורידים את החלקים שעולים כסף. ברירת המחדל היא שכולם פעילים.
- `-var eks_version=1.30` (או גרסה אחרת ב-extended support) שותל את eks-old-version. עולה בערך 365$ לחודש נוספים.
- `-var codebuild_webhook_repo_url=https://github.com/<you>/<throwaway>` מוסיף את ה-webhook הלא מעוגן. צריך קודם `aws codebuild import-source-credentials` עם PAT.

**לפני הריצה, לוודא שה-absence plants באמת חסרים.** אלה ה-plants של "אין GuardDuty / Config / Access Analyzer / Budgets / password policy / SECURITY contact / Bedrock logging". מריצים את פקודות ה-`detect_read_only` של ה-plants עם `kind: absence` ב-YAML. אם משהו כבר מופעל בחשבון, מעבירים ל-score.py את `--disable absence_intact` או מתעלמים מהשורה הזו.

## שלב 3 — יצירת גישה לבוט (read-only)
```bash
cd ../access
terraform init
terraform apply -var sandbox_account_id=<12 digits>
terraform output AWS_ROLE_ARN
terraform output -raw AWS_EXTERNAL_ID
AWS_PROFILE=roqy-sandbox-admin ./create-bot-key.sh     # prints the key ONCE, not stored in tfstate
```
מה נוצר:
- **`roqy-audit-sandbox`** — role עם SecurityAudit ו-ViewOnlyAccess, ועם אותה רשימת Deny על כתיבה שיש ב-`cloudformation/audit-role.yaml`. בנוסף יש Deny על קריאת ערכי סודות (GetSecretValue, GetParameter, kms:Decrypt, s3:GetObject), על Start/Stop, על StartBuild ועוד. כדי להניח אותו צריך ExternalId.
- **`roqy-auditor-bot`** — ההרשאה היחידה שלו היא `sts:AssumeRole` על ה-role הזה, עם ה-ExternalId. כל השאר חסום ב-Deny מפורש. אפשר לנעול אותו גם ל-IP עם `-var 'allowed_source_cidrs=["x.x.x.x/32"]'`.
- למה זה לא ה-CloudFormation מהרפו: ב-template הפרמטר `AuditAccountPrincipalArn` מקבל רק `:role/`. ל-sandbox בנינו את אותו role ב-Terraform, עם המשתמש בתור principal. אצל לקוחות אמיתיים ממשיכים להשתמש ב-CFN.

בדיקה עצמית (עם המפתח של הבוט):
```bash
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... ROLE_ARN=... EXTERNAL_ID=... ./verify-access.sh
```
הסקריפט מוודא שהמפתח לבד לא יכול לעשות כלום, שה-assume עובד, שקריאה עובדת ושכתיבה נחסמת. הכתיבה נבדקת עם `--dry-run` בלבד.

## שלב 4 — מה שולחים לבוט של רון
| ערך | סוג | איך שולחים |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | סוד | רק דרך טופס הסודות המוצפן בצ'אט. לא בהודעה רגילה |
| `AWS_SECRET_ACCESS_KEY` | סוד | רק דרך טופס הסודות המוצפן בצ'אט |
| `AWS_ROLE_ARN` | לא סודי | בצ'אט |
| `AWS_EXTERNAL_ID` | לא סודי (אבל לא לפרסם) | בצ'אט או בטופס |
| `AWS_REGION` | `eu-central-1` | בצ'אט |
| מזהה חשבון ה-sandbox, ואילו `-var` הופעלו (allow_public, foreign_account, rds, eks, weak_trail) | לא סודי | בצ'אט. נדרש בשביל ה-scoring |

## שלב 5 — הרצת האודיט
הבוט מגדיר את המפתח כמשתני סביבה, ומריץ את ה-harness עם profile שמניח את ה-role:
```bash
aws configure set role_arn "$AWS_ROLE_ARN" --profile roqy-audit
aws configure set external_id "$AWS_EXTERNAL_ID" --profile roqy-audit
aws configure set credential_source Environment --profile roqy-audit
aws configure set region eu-central-1 --profile roqy-audit
AWS_PROFILE=roqy-audit aws sts get-caller-identity
# then run live-infra-audit / Hermes harness with AWS_PROFILE=roqy-audit -> findings.json + report.md
```

## שלב 6 — ניקוד
```bash
pip install pyyaml
python scripts/validate_commands.py                       # every aws command in the YAML exists
python scripts/score.py findings.json                     # default config (instance+rds+eks on)
python scripts/score.py findings.json --disable eks,rds    # if you applied with enable_eks/enable_rds=false
python scripts/score.py report.md --enable allow_public,foreign_account --json score.json --fail-under 90
```
הפלט כולל:
- טבלה עם DETECTED, MISSED וחוסר התאמה בחומרה
- כיסוי לכל קטגוריה
- רשימת ה-checks מסוג `NEW-*` שעוד צריך לממש
- ממצאים שלא התאימו לשום plant (חשד ל-false positive)
- אחוז כיסוי כולל

ממצא אחד מוכיח plant אחד בלבד. כלומר, W2 על פורטים פתוחים לא "מכסה" גם את ה-SG של all-traffic.

## הרחבה: המעטפת של הענן (Terraform, Kubernetes, Helm, CI/CD)
Prowler ו-Security Hub מסתכלים על מצב הענן ברגע הבדיקה. הם לא רואים איך הוא נבנה, מה ישתנה ב-deploy הבא, ומה רץ בתוך ה-cluster. ההרחבה הזו שותלת 50 חולשות בקטגוריות c19 עד c27 (36 המעטפת המקורית + 14 שרשרת אספקה של Docker/תלויות וסוכני AI), ומודדת אם roqy-audit תופס אותן.

| קטגוריה | מה נשתל | איפה |
|---|---|---|
| c19 Terraform state | באקט state בלי versioning, רק SSE-S3, policy שנותנת לכל principal בחשבון לקרוא ולדרוס, backend בלי lock, סיסמת DB בתוך ה-state, סיסמה כ-default של משתנה | `envelope/`, `client-repo/infra/` |
| c20 Drift | פורט 22 נפתח ל-0.0.0.0/0 ידנית דרך CLI, ו-tag של Owner שונה | security group בשם `roqy-lab-client-web` |
| c21 Supply chain | module מ-git בלי `ref`, providers בלי גרסה, `.terraform.lock.hcl` ב-gitignore, `aws_ami` בלי `owners` | `client-repo/infra/` |
| c22 CI/CD | `terraform apply` על כל PR עם מפתחות AWS קבועים, `pull_request_target` עם checkout של ה-PR, סודות שזמינים ל-forks, `write-all`, actions לא נעולים ל-SHA, בלי OIDC | `client-repo/.github/workflows/` |
| c23 Kubernetes | pod privileged, hostPath `/`, hostNetwork, IMDS נגיש מ-pods (hop limit 2), IRSA ל-role רחב, automount של ה-default SA, בלי NetworkPolicy, cluster-admin ל-ServiceAccount, סוד כ-env, `:latest` מ-Docker Hub, בלי limits | `k8s/plants.yaml` |
| c24 Helm | values עם סיסמה ומפתח Stripe בטקסט גלוי (נשמרים ב-`sh.helm.release.v1.*`), ConfigMap ו-env עם סודות, helmfile עם repo ב-http בלי אימות ובלי גרסה, image `latest` | `helm/`, `client-repo/deploy/` |
| c25 שרשראות תקיפה | PR, אחריו apply עם מפתחות admin, ומשם החשבון. pod פרוץ, אחריו IMDS, ה-role של ה-node, ו-S3. state דולף, ממנו סיסמת DB, ומשם RDS ציבורי | מתאם בין הממצאים |
| c26 Docker ותלויות | `FROM` עם `latest` בלי digest, `curl\|bash` ב-Dockerfile וב-CI, image בסיס EOL, `requirements.txt` בלי pin, `package.json` בלי lockfile, `pip install` לא נעול ב-Dockerfile, Renovate בלי `minimumReleaseAge`, `ADD` מ-URL בלי checksum | `client-repo/Dockerfile`, `requirements.txt`, `package.json`, `renovate.json`, `.github/workflows/docker-build.yml` |
| c27 שרשרת סוכן AI | skill עם prompt injection / HTML comment / exfil, סקריפט התקנה עם `curl\|bash`, MCP עם `npx -y`/`@latest`/git בלי SHA, סודות מזויפים ב-env, filesystem MCP על `/` | `client-repo/.claude/skills/`, `.cursor/mcp.json`, `.cursor/rules/`, `AGENTS.md` |

כל הסודות מזויפים. ה-role של IRSA מוגבל ב-permissions boundary מסוג deny-all, כך שהוא נראה לאודיט אבל לא עובד בפועל. ל-role של ה-node נוספה קריאת S3 על `*` כדי שהשרשרת pod → IMDS → S3 תהיה אמיתית. אפשר להגיע אליו רק מ-pods על ה-node של המעבדה.

### הקמה (admin בלבד, אחרי `terraform/` ו-`access/`)
```bash
export SANDBOX_ACCOUNT_ID=<12 digits>
# kubeconfig with an explicit admin context named roqy-lab-admin (never rely on current-context)
scripts/apply-envelope.sh
```
הסקריפט מריץ את `envelope/`, עושה apply ל-`client-repo/infra` עם remote state לבאקט הפגיע, יוצר את ה-drift דרך CLI, ומתקין את `k8s/` ואת ה-Helm release. ב-`access/` נוספו access entry ל-EKS עם `AmazonEKSViewPolicy` עבור ה-role של האודיט, וקבוצת `roqy-audit-rbac-read` (`k8s/audit-rbac-reader.yaml`) שנותנת קריאה של אובייקטי RBAC בלבד.

**חשוב:** ה-hop limit של ה-node לא היה 2. ב-AL2023 הוא היה 1 עם IMDSv2 חובה. ה-envelope משנה אותו ל-2 ישירות על המכונה. אם ה-node מוחלף, צריך להריץ שוב את `scripts/apply-envelope.sh`.

### הרצת האודיט וניקוד
```bash
python3 lab-run/audit_envelope.py --repo vuln-lab/client-repo --redacted-state lab-run/envelope/client-state.redacted.json
python3 vuln-lab/scripts/score.py lab-run/envelope/findings-envelope.json --categories c19,c20,c21,c22,c23,c24,c25,c26,c27
```

### איך זה נשאר read-only
- **AWS:** רק דרך ה-role לקריאה בלבד, ורק עם פעלים מרשימה סגורה (`describe`, `get`, `list`, `head`).
- **kubectl ו-Helm:** תמיד עם `--context roqy-lab-audit-ro` או `--kube-context`, ורק `get` ו-`auth can-i`. אף פעם לא `get secrets`.
- **Terraform state:** בודקים רק metadata של הבאקט ושמות של קבצים. ל-role יש deny מפורש על `s3:GetObject`, וזה גובר גם על ה-policy הרחבה של הבאקט. ממצא שדורש את תוכן ה-state מסומן `needs_validation`.
- **Drift:** הלקוח מריץ `terraform state pull | scripts/redact-state.py` ושולח JSON בלי סודות. האודיט משווה אותו לקריאות `describe` ול-tagging API. ניסינו גם `terraform plan -lock=false -refresh=true` עם ה-role לקריאה בלבד, על עותק זמני וב-backend מקומי. הוא מצא את ה-drift, אבל נכשל ב-`ssm:GetParameter`, כי refresh מנסה לקרוא את ערך הסוד. בנוסף הוא דורש את ה-state המלא, כולל הסיסמה, על המכונה של האודיט. לכן השיטה הראשית היא ההשוואה, ו-plan מורץ רק אצל הלקוח.
- **Helm:** `AmazonEKSViewPolicy` לא קורא Secrets, אפילו לא את השמות שלהם, ולכן `helm list` נכשל בכוונה. מזהים releases לפי ה-labels וה-annotations של Helm. הסודות ב-values מוכחים מה-manifests שנוצרו: env ו-ConfigMap, ובדוח מופיעים רק שמות המפתחות. כדי לאמת את המפתחות המדויקים הלקוח מריץ `scripts/helm-values-keys.sh`, שמדפיס שמות בלבד. לא עוברים ל-`AmazonEKSAdminViewPolicy`, כי הוא כן קורא ערכי Secrets.
- **RBAC:** ה-view הרגיל לא רואה (Cluster)RoleBindings. בלי קבוצת `roqy-audit-rbac-read`, ה-SA עם cluster-admin לא נתפס והכיסוי יורד ל-35/36.

### עלות נוספת
כמעט אפס, פחות מ-$0.10 לחודש. יש באקט S3 קטן, OIDC provider, roles, launch template שלא מריצים ממנו, SSM Standard ו-5 pods קטנים על ה-node שכבר קיים (t4g.small מאפשר 11 pods, ו-9 תפוסים). לא נוספו מכונות, NAT או Load Balancer.

## שלב 7 — פירוק (חובה בסוף)
```bash
# envelope first (explicit contexts):
helm --kube-context roqy-lab-admin uninstall roqy-lab-payments -n roqy-lab-apps
kubectl --context roqy-lab-admin delete -f k8s/plants.yaml -f k8s/audit-rbac-reader.yaml
(cd client-repo/infra && terraform destroy)   # revoke the manual port-22 rule first if destroy complains
(cd envelope && terraform destroy -var sandbox_account_id=<id>)
cd access    && terraform destroy -var sandbox_account_id=<id>
# delete the bot key first if destroy complains:
aws iam list-access-keys --user-name roqy-auditor-bot --profile roqy-sandbox-admin
aws iam delete-access-key --user-name roqy-auditor-bot --access-key-id <id> --profile roqy-sandbox-admin
cd ../terraform && terraform destroy
```
- ה-KMS keys נכנסים ל-pending deletion ונמחקים אחרי 7 עד 30 יום, בלי עלות בזמן ההמתנה.
- אם `allow_public=true` הופעל, ה-destroy מבטל קודם את השיתוף הציבורי של ה-snapshot.
- אחרי ה-destroy כדאי לוודא שלא נשאר כלום:
  ```bash
  aws resourcegroupstaggingapi get-resources --tag-filters Key=roqy-lab,Values=true --region eu-central-1 --profile roqy-sandbox-admin
  aws resourcegroupstaggingapi get-resources --tag-filters Key=roqy-lab,Values=true --region us-east-1 --profile roqy-sandbox-admin
  ```

## מה לא נשתל ולמה
- **SES production access:** דורש בקשה ל-AWS Support. ה-plant הוא identity בלבד, בחומרה P3 כמידע.
- **Lambda על runtime שכבר EOL (W17):** AWS כבר לא מאפשרת ליצור פונקציות כאלה.
- **מפתחות IAM ישנים מ-90 יום (W3):** אי אפשר לזייף גיל. לכן ה-plant הוא "מפתח שמעולם לא נעשה בו שימוש" (W11).
- **Secrets Manager בלי rotation (W37):** הכלל של W37 דורש גיל מעל 90 יום, ולכן ה-plant כבוי כברירת מחדל.
- **CodeBuild webhook לא מעוגן:** צריך GitHub source credentials, ולכן הוא אופציונלי.
- **Root בלי MFA ו-root access keys (W4, W40):** לא נוגעים ב-root של ה-sandbox. אם ל-root של ה-sandbox אין MFA, האודיט אמור לתפוס את זה. זה ממצא אמיתי ולא plant.
- **S3 עם ACL ל-AuthenticatedUsers (W38):** ב-bucket חדש ה-ACLs חסומים (BucketOwnerEnforced). אפשרי רק דרך policy.
- **SCPs (W16):** דורש AWS Organizations. חשבון sandbox בודד לא מכסה את זה.
- **Name confusion ב-AMIs:** מכוסה ברמת החשבון (Allowed AMIs כבוי), ובצד הרפו דרך `iac-samples/whoami.tf.example`.
- **Dangling DNS ב-zone ציבורי:** ברירת המחדל היא private zone. zone ציבורי עם CNAME תלוי שמואצל באמת ניתן להשתלטות, ולכן לא עושים את זה.
