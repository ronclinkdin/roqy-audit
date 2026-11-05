#!/usr/bin/env bash
# Creates the access key for roqy-auditor-bot OUTSIDE terraform, so the secret never lands in tfstate.
# Prints it once. Paste the two values into the Grok Bot secret form, then clear your terminal.
set -euo pipefail
PROFILE="${AWS_PROFILE:-roqy-sandbox-admin}"
COUNT=$(aws iam list-access-keys --user-name roqy-auditor-bot --profile "$PROFILE" --query 'length(AccessKeyMetadata)' --output text)
if [ "$COUNT" != "0" ]; then
  echo "roqy-auditor-bot already has $COUNT key(s). Delete the old one first:"
  echo "  aws iam list-access-keys --user-name roqy-auditor-bot --profile $PROFILE"
  echo "  aws iam delete-access-key --user-name roqy-auditor-bot --access-key-id <id> --profile $PROFILE"
  exit 1
fi
aws iam create-access-key --user-name roqy-auditor-bot --profile "$PROFILE" \
  --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text |
  awk '{print "AWS_ACCESS_KEY_ID=" $1 "\nAWS_SECRET_ACCESS_KEY=" $2}'
