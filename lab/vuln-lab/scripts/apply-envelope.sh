#!/usr/bin/env bash
# Deploy the ENVELOPE extension (after ../terraform and ../access are applied). ADMIN profile only.
# Usage: SANDBOX_ACCOUNT_ID=<12 digits> KUBECONFIG=<file with context roqy-lab-admin> scripts/apply-envelope.sh
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SANDBOX_ACCOUNT_ID:?set SANDBOX_ACCOUNT_ID}"
PROFILE="${AWS_PROFILE_ADMIN:-roqy-sandbox-admin}"; REGION=eu-central-1; CTX="${ADMIN_CONTEXT:-roqy-lab-admin}"
[ "$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)" = "$SANDBOX_ACCOUNT_ID" ] || { echo "wrong account"; exit 1; }

# 1. cloud side (state bucket, IRSA, node role S3, node hop limit 2)
( cd envelope && terraform init -input=false && terraform apply -input=false -auto-approve -var sandbox_account_id="$SANDBOX_ACCOUNT_ID" -var aws_profile="$PROFILE" )
BUCKET=$(cd envelope && terraform output -raw client_state_bucket); IRSA=$(cd envelope && terraform output -raw irsa_role_arn)

# 2. fake client project -> remote state in the bad bucket
sed -i "s/roqy-lab-client-tfstate-[a-z0-9]*/$BUCKET/" client-repo/infra/backend.tf
sed -i "s/\"[0-9]\{12\}\"\] # lab guard/\"$SANDBOX_ACCOUNT_ID\"] # lab guard/" client-repo/infra/versions.tf
( cd client-repo/infra && AWS_PROFILE=$PROFILE terraform init -input=false -reconfigure && AWS_PROFILE=$PROFILE terraform apply -input=false -auto-approve )

# 3. DRIFT: out-of-band console-style changes (code != cloud)
SG=$(aws ec2 describe-security-groups --profile "$PROFILE" --region $REGION --filters Name=group-name,Values=roqy-lab-client-web --query 'SecurityGroups[0].GroupId' --output text)
aws ec2 authorize-security-group-ingress --profile "$PROFILE" --region $REGION --group-id "$SG" \
  --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0,Description="temp debug - remove later"}]' >/dev/null 2>&1 || true
aws ec2 create-tags --profile "$PROFILE" --region $REGION --resources "$SG" --tags Key=Owner,Value=someone-in-console Key=hotfix,Value=2026-11-04

# 4. Kubernetes + Helm (explicit context, always)
kubectl --context "$CTX" apply -f k8s/audit-rbac-reader.yaml   # RBAC-object read for the audit group (access/ maps it)
sed "s#__IRSA_ROLE_ARN__#$IRSA#" k8s/plants.yaml | kubectl --context "$CTX" apply -f -
helm --kube-context "$CTX" upgrade --install roqy-lab-payments helm/roqy-lab-payments -n roqy-lab-apps -f helm/values-prod.yaml
echo "envelope deployed: state bucket $BUCKET, IRSA $IRSA"
