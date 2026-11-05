#!/usr/bin/env bash
# Run with the BOT key in env (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY) + ROLE_ARN + EXTERNAL_ID.
# Proves: (1) the key alone can do nothing, (2) it can assume the role, (3) the role cannot write.
set -uo pipefail
unset AWS_PROFILE
REGION="${AWS_REGION:-eu-central-1}"
echo "== whoami (key)"; aws sts get-caller-identity
echo "== key alone must be denied:"; aws s3api list-buckets >/dev/null 2>&1 && echo "FAIL: key can list buckets" || echo "OK denied"
CREDS=$(aws sts assume-role --role-arn "$ROLE_ARN" --external-id "$EXTERNAL_ID" --role-session-name roqy-verify \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text) || { echo "FAIL: assume-role"; exit 1; }
read -r AK SK ST <<<"$CREDS"
export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_SESSION_TOKEN=$ST
echo "== whoami (role)"; aws sts get-caller-identity
echo "== read works:"; aws iam get-account-summary --query 'SummaryMap.Users' --output text
echo "== write must be denied (dry-run only, nothing is created):"
aws ec2 create-security-group --group-name roqy-probe --description probe --dry-run --region "$REGION" 2>&1 | grep -q UnauthorizedOperation && echo "OK denied" || echo "CHECK: unexpected response"
aws ssm get-parameter --name /roqy-lab/prod/db_master_password --region "$REGION" >/dev/null 2>&1 && echo "FAIL: role can read parameter values" || echo "OK parameter values denied"
