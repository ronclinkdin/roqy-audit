terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80.0, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}

variable "sandbox_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.sandbox_account_id))
    error_message = "12-digit account id."
  }
}

variable "aws_profile" {
  type    = string
  default = "roqy-sandbox-admin"
}

variable "region" {
  type    = string
  default = "eu-central-1"
}

variable "allowed_source_cidrs" {
  description = "Optional: egress IP CIDRs of Ron's bot box. Empty = no IP pinning (key is still only able to assume the audit role)."
  type        = list(string)
  default     = []
}

provider "aws" {
  region              = var.region
  profile             = var.aws_profile
  allowed_account_ids = [var.sandbox_account_id]
  default_tags {
    tags = { "roqy-access" = "true", "managed-by" = "terraform-roqy-vuln-lab-access" }
  }
}

data "aws_caller_identity" "current" {}

resource "random_password" "external_id" {
  length  = 32
  special = false
}


############################################################
# 1. The bot user. ONLY permission: sts:AssumeRole on the audit role (with ExternalId).
############################################################
resource "aws_iam_user" "bot" {
  name          = "roqy-auditor-bot"
  path          = "/roqy/"
  force_destroy = true
}

resource "aws_iam_user_policy" "bot_assume_only" {
  name = "assume-roqy-audit-role-only"
  user = aws_iam_user.bot.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AssumeAuditRoleOnly"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.audit.arn
        Condition = merge(
          { StringEquals = { "sts:ExternalId" = random_password.external_id.result } },
          length(var.allowed_source_cidrs) > 0 ? { IpAddress = { "aws:SourceIp" = var.allowed_source_cidrs } } : {}
        )
      },
      {
        Sid    = "DenyEverythingElse"
        Effect = "Deny"
        NotAction = [
          "sts:AssumeRole",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      {
        Sid         = "DenyAssumingAnyOtherRole"
        Effect      = "Deny"
        Action      = "sts:AssumeRole"
        NotResource = aws_iam_role.audit.arn
      }
    ]
  })
}

############################################################
# 2. Read-only audit role. Mirrors cloudformation/audit-role.yaml from roqy-audit:
#    SecurityAudit + ViewOnlyAccess, explicit deny on writes, ExternalId required.
#    (The CFN template's AuditAccountPrincipalArn only accepts a :role/ ARN, so for the
#    sandbox the same role is built here with the bot user as principal.)
############################################################
resource "aws_iam_role" "audit" {
  name                 = "roqy-audit-sandbox"
  max_session_duration = 14400
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = aws_iam_user.bot.arn }
      Action    = "sts:AssumeRole"
      Condition = { StringEquals = { "sts:ExternalId" = random_password.external_id.result } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.audit.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "view_only" {
  role       = aws_iam_role.audit.name
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "deny_writes" {
  name = "ExplicitDenyWrites"
  role = aws_iam_role.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Same list as cloudformation/audit-role.yaml
        Sid    = "DenyAllWrites"
        Effect = "Deny"
        Action = [
          "s3:Put*", "s3:Delete*",
          "ec2:Create*", "ec2:Delete*", "ec2:Modify*", "ec2:Authorize*", "ec2:Revoke*", "ec2:RunInstances",
          "iam:Create*", "iam:Delete*", "iam:Put*", "iam:Attach*", "iam:Detach*", "iam:Update*",
          "lambda:Create*", "lambda:Delete*", "lambda:Update*", "lambda:Invoke*",
          "secretsmanager:Put*", "secretsmanager:Delete*", "secretsmanager:Rotate*",
          "kms:Create*", "kms:Delete*", "kms:Put*", "kms:Schedule*",
          "logs:Put*", "logs:Delete*",
          "sns:Publish", "sns:Create*", "sns:Delete*", "sns:Set*",
          "sqs:Send*", "sqs:Create*", "sqs:Delete*",
          "sts:AssumeRole"
        ]
        Resource = "*"
      },
      {
        # Sandbox extras: never read secret VALUES or object data, never start/stop anything.
        Sid    = "DenySecretValuesAndActions"
        Effect = "Deny"
        Action = [
          "secretsmanager:GetSecretValue",
          "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath",
          "kms:Decrypt", "kms:GenerateDataKey*",
          "s3:GetObject", "s3:GetObjectVersion",
          "ec2:StartInstances", "ec2:StopInstances", "ec2:TerminateInstances",
          "ec2:GetPasswordData",
          "codebuild:StartBuild", "codebuild:BatchGetBuilds",
          "ssm:SendCommand", "ssm:StartSession",
          "cognito-idp:Admin*", "cognito-identity:GetCredentialsForIdentity",
          "bedrock:InvokeModel*",
          "ecr:GetAuthorizationToken", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
          "rds:Modify*", "rds:Delete*", "rds:Create*",
          "eks:Create*", "eks:Delete*", "eks:Update*", "eks:Associate*",
          "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:Update*",
          "guardduty:*Delete*", "guardduty:Update*", "guardduty:Create*",
          "organizations:*Delete*", "organizations:Create*", "organizations:Update*",
          "account:Put*", "account:Delete*"
        ]
        Resource = "*"
      }
    ]
  })
}

############################################################
# 2b. Read-only extras that SecurityAudit + ViewOnlyAccess do not include.
#     All are metadata reads (no secret values, no data plane):
#       budgets/ce      -> W7 (no budgets), W23 (no cost anomaly monitor)
#       elasticbeanstalk:CheckDNSAvailability -> NEW-DANGLING-DNS (EB CNAME claimable?)
#       ssm:GetDocument -> shared/public SSM documents content (no parameters)
#       savingsplans    -> FinOps context
############################################################
resource "aws_iam_role_policy" "read_extras" {
  name = "RoqyReadOnlyExtras"
  role = aws_iam_role.audit.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "ReadOnlyExtras"
      Effect = "Allow"
      Action = [
        "budgets:ViewBudget",
        "ce:GetAnomalyMonitors",
        "ce:GetAnomalySubscriptions",
        "elasticbeanstalk:CheckDNSAvailability",
        "ssm:GetDocument",
        "savingsplans:DescribeSavingsPlans"
      ]
      Resource = "*"
    }]
  })
}

output "AWS_ROLE_ARN" {
  value = aws_iam_role.audit.arn
}

output "AWS_EXTERNAL_ID" {
  description = "Non-secret per spec, but keep it out of public places."
  value       = random_password.external_id.result
  sensitive   = true
}

output "bot_user_name" {
  value = aws_iam_user.bot.name
}

############################################################
# 3. Kubernetes read-only for the audit role (envelope extension).
#    AmazonEKSViewPolicy == k8s "view" ClusterRole: no Secrets (not even names), no RBAC objects.
#    Do NOT swap to AmazonEKSAdminViewPolicy: that one CAN read Secret values (incl. Helm release
#    secrets), which breaks the "we never saw a secret" promise.
############################################################
variable "eks_cluster_name" {
  description = "Lab EKS cluster to grant the audit role view access on. Empty = skip."
  type        = string
  default     = "roqy-lab-eks"
}

resource "aws_eks_access_entry" "audit_view" {
  count         = var.eks_cluster_name == "" ? 0 : 1
  cluster_name  = var.eks_cluster_name
  principal_arn = aws_iam_role.audit.arn
  type          = "STANDARD"
  # + RBAC-object read (ClusterRole in ../k8s/audit-rbac-reader.yaml): view cannot see (Cluster)RoleBindings,
  #   so "SA bound to cluster-admin" would otherwise be invisible. Still no Secrets.
  kubernetes_groups = ["roqy-audit-rbac-read"]
}

resource "aws_eks_access_policy_association" "audit_view" {
  count         = var.eks_cluster_name == "" ? 0 : 1
  cluster_name  = var.eks_cluster_name
  principal_arn = aws_iam_role.audit.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSViewPolicy"
  access_scope {
    type = "cluster"
  }
  depends_on = [aws_eks_access_entry.audit_view]
}
