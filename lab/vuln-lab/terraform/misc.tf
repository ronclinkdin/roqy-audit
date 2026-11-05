############################################################
# c14  SSM String (not SecureString) parameter named like a password
############################################################
resource "aws_ssm_parameter" "plain_password" {
  name  = "/roqy-lab/prod/db_master_password"
  type  = "String"
  value = local.fake.db_pass
  tags  = { "roqy-plant" = "ssm-string-password" }
}

resource "aws_secretsmanager_secret" "no_rotation" {
  count                   = var.enable_secrets_manager ? 1 : 0
  name                    = "roqy-lab/prod/stripe-${local.sfx}"
  recovery_window_in_days = 0
  tags                    = { "roqy-plant" = "secretsmanager-no-rotation" }
}

resource "aws_secretsmanager_secret_version" "no_rotation" {
  count         = var.enable_secrets_manager ? 1 : 0
  secret_id     = aws_secretsmanager_secret.no_rotation[0].id
  secret_string = local.fake.stripe
}

############################################################
# KMS: cross-account key policy, no rotation; second key scheduled for deletion
############################################################
resource "aws_kms_key" "shared" {
  description             = "roqy-lab shared data key (PLANT kms-cross-account-policy / kms-no-rotation)"
  enable_key_rotation     = false
  deletion_window_in_days = 7
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }],
      local.has_foreign ? [{
        Sid       = "PartnerDecrypt"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.foreign_account_id}:root" }
        Action    = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey*"]
        Resource  = "*"
      }] : []
    )
  })
  tags = { "roqy-plant" = "kms-cross-account-policy kms-no-rotation" }
}

resource "aws_kms_alias" "shared" {
  name          = "alias/roqy-lab-shared-data"
  target_key_id = aws_kms_key.shared.key_id
}

# PLANT kms-pending-deletion.
# Managed ONLY through the CLI on purpose: the AWS provider reads a PendingDeletion key as "deleted",
# so a TF-managed key gets silently re-created (Enabled) on the next apply and the plant disappears
# (observed on the first sandbox run, 2026-11-04). Create/point alias/schedule is idempotent.
resource "terraform_data" "doom_key" {
  count = var.schedule_kms_deletion ? 1 : 0
  input = {
    alias   = "alias/roqy-lab-prod-backups"
    region  = var.region
    profile = var.aws_profile
  }
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      A="${self.input.alias}"; R="--region ${self.input.region} --profile ${self.input.profile}"
      K=$(aws kms list-aliases $R --query "Aliases[?AliasName=='$A'].TargetKeyId | [0]" --output text)
      if [ "$K" = "None" ] || [ -z "$K" ]; then
        K=$(aws kms create-key $R --description "roqy-lab key that holds 'production' data and is pending deletion (PLANT kms-pending-deletion)" \
             --tags TagKey=roqy-lab,TagValue=true TagKey=roqy-plant,TagValue=kms-pending-deletion --query KeyMetadata.KeyId --output text)
        aws kms create-alias $R --alias-name "$A" --target-key-id "$K"
      fi
      S=$(aws kms describe-key $R --key-id "$K" --query KeyMetadata.KeyState --output text)
      [ "$S" = "PendingDeletion" ] || aws kms schedule-key-deletion $R --key-id "$K" --pending-window-in-days 30 >/dev/null
      echo "doom key $K: $(aws kms describe-key $R --key-id "$K" --query KeyMetadata.KeyState --output text)"
    EOT
  }
  provisioner "local-exec" {
    when        = destroy
    on_failure  = continue
    interpreter = ["/bin/bash", "-c"]
    # Key stays PendingDeletion and deletes itself; only the alias is removed.
    command = "aws kms delete-alias --alias-name ${self.input.alias} --region ${self.input.region} --profile ${self.input.profile}"
  }
}

############################################################
# SNS / SQS with Principal "*"
############################################################
resource "aws_sns_topic" "open" {
  name = "roqy-lab-order-events"
  tags = { "roqy-plant" = "sns-principal-star" }
}

resource "aws_sns_topic_policy" "open" {
  arn = aws_sns_topic.open.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AnyonePublishPLANT"
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = ["SNS:Publish", "SNS:Subscribe"]
      Resource  = aws_sns_topic.open.arn
    }]
  })
}

resource "aws_sqs_queue" "open" {
  name                      = "roqy-lab-jobs"
  message_retention_seconds = 60
  tags                      = { "roqy-plant" = "sqs-principal-star" }
}

resource "aws_sqs_queue_policy" "open" {
  queue_url = aws_sqs_queue.open.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AnyoneSendPLANT"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["sqs:SendMessage"]
      Resource  = aws_sqs_queue.open.arn
    }]
  })
}

############################################################
# ECR: scan-on-push off, mutable tags, optional public pull
############################################################
resource "aws_ecr_repository" "sloppy" {
  name                 = "roqy-lab/api"
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = false
  }
  tags = { "roqy-plant" = "ecr-scan-off-mutable ecr-public-pull" }
}

resource "aws_ecr_repository_policy" "public_pull" {
  count      = var.allow_public ? 1 : 0
  repository = aws_ecr_repository.sloppy.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicPullPLANT"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "ecr:BatchCheckLayerAvailability"]
    }]
  })
}

############################################################
# c13  CodeBuild: privileged mode + plaintext secret env + over-privileged role
############################################################
resource "aws_iam_role" "codebuild" {
  name = "roqy-lab-codebuild"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "codebuild.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { "roqy-plant" = "codebuild-privileged-plaintext-env" }
}

resource "aws_iam_role_policy" "codebuild" {
  name = "deploy-everything"
  role = aws_iam_role.codebuild.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "iam:CreateRole", "iam:AttachRolePolicy", "s3:*", "lambda:*", "ecr:*", "logs:*"]
      Resource = "*"
    }]
  })
}

resource "aws_codebuild_project" "insecure" {
  name          = "roqy-lab-deploy"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 5

  artifacts {
    type = "NO_ARTIFACTS"
  }

  environment {
    compute_type    = "BUILD_GENERAL1_SMALL"
    image           = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type            = "LINUX_CONTAINER"
    privileged_mode = true

    environment_variable {
      name  = "GITHUB_TOKEN"
      value = local.fake.gh_token
      type  = "PLAINTEXT"
    }
    environment_variable {
      name  = "AWS_SECRET_ACCESS_KEY"
      value = local.fake.aws_secret
      type  = "PLAINTEXT"
    }
  }

  source {
    type      = "NO_SOURCE"
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo roqy-lab never runs this\n"
  }

  tags = { "roqy-plant" = "codebuild-privileged-plaintext-env" }
}

# Optional: CodeBreach-style unanchored ACTOR_ACCOUNT_ID webhook filter. Needs GitHub source creds.
resource "aws_codebuild_project" "webhook" {
  count         = var.codebuild_webhook_repo_url == "" ? 0 : 1
  name          = "roqy-lab-pr-builder"
  service_role  = aws_iam_role.codebuild.arn
  build_timeout = 5
  artifacts {
    type = "NO_ARTIFACTS"
  }
  environment {
    compute_type = "BUILD_GENERAL1_SMALL"
    image        = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"
    type         = "LINUX_CONTAINER"
  }
  source {
    type      = "GITHUB"
    location  = var.codebuild_webhook_repo_url
    buildspec = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo roqy-lab\n"
  }
  tags = { "roqy-plant" = "codebuild-unanchored-webhook" }
}

resource "aws_codebuild_webhook" "unanchored" {
  count        = var.codebuild_webhook_repo_url == "" ? 0 : 1
  project_name = aws_codebuild_project.webhook[0].name
  filter_group {
    filter {
      type    = "EVENT"
      pattern = "PULL_REQUEST_CREATED,PULL_REQUEST_UPDATED"
    }
    filter {
      type    = "ACTOR_ACCOUNT_ID"
      pattern = "12345678|87654321" # PLANT: no ^...$ anchors -> any ID containing these digits matches
    }
  }
}

############################################################
# c18  Logging: no trail by default; optional weak trail; log group w/o retention (lambda.tf)
############################################################
resource "aws_s3_bucket" "trail" {
  count         = var.create_weak_trail ? 1 : 0
  bucket        = "roqy-lab-trail-${local.sfx}"
  force_destroy = true
  tags          = { "roqy-plant" = "cloudtrail-single-region-novalidation" }
}

resource "aws_s3_bucket_policy" "trail" {
  count  = var.create_weak_trail ? 1 : 0
  bucket = aws_s3_bucket.trail[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail[0].arn
      },
      {
        Sid       = "Write"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail[0].arn}/AWSLogs/${local.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

resource "aws_cloudtrail" "weak" {
  count                         = var.create_weak_trail ? 1 : 0
  name                          = "roqy-lab-trail"
  s3_bucket_name                = aws_s3_bucket.trail[0].id
  is_multi_region_trail         = false
  include_global_service_events = false
  enable_log_file_validation    = false
  tags                          = { "roqy-plant" = "cloudtrail-single-region-novalidation" }
  depends_on                    = [aws_s3_bucket_policy.trail]
}

# Absence plants (never created): GuardDuty detector, AWS Config recorder, IAM Access Analyzer,
# Security Hub, Budgets, Cost Anomaly monitor, Bedrock invocation logging, SECURITY alternate contact.

############################################################
# c11  Dangling DNS (private zone by default -> no takeover risk)
############################################################
resource "aws_route53_zone" "lab" {
  count = var.dns_zone_type == "none" ? 0 : 1
  name  = var.dns_domain
  dynamic "vpc" {
    for_each = var.dns_zone_type == "private" ? [1] : []
    content {
      vpc_id = aws_vpc.lab.id
    }
  }
  force_destroy = true
  tags          = { "roqy-plant" = "r53-dangling-cname-s3 r53-dangling-cname-eb" }
}

resource "aws_route53_record" "dangling_s3" {
  count   = var.dns_zone_type == "none" ? 0 : 1
  zone_id = aws_route53_zone.lab[0].zone_id
  name    = "assets.${var.dns_domain}"
  type    = "CNAME"
  ttl     = 300
  records = ["roqy-lab-deleted-assets-${local.sfx}.s3-website.${var.region}.amazonaws.com"]
}

resource "aws_route53_record" "dangling_eb" {
  count   = var.dns_zone_type == "none" ? 0 : 1
  zone_id = aws_route53_zone.lab[0].zone_id
  name    = "app.${var.dns_domain}"
  type    = "CNAME"
  ttl     = 300
  records = ["roqy-lab-old-env-${local.sfx}.${var.region}.elasticbeanstalk.com"]
}

############################################################
# c10  SES identity (sandbox-mode SES; domain identity, no email is sent)
############################################################
resource "aws_sesv2_email_identity" "domain" {
  email_identity = "mail.roqy-lab-${local.sfx}.example"
  tags           = { "roqy-plant" = "ses-domain-identity" }
}
