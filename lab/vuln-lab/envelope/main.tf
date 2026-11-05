# roqy vuln-lab ENVELOPE extension: the cloud "envelope" that Prowler / Security Hub do not see.
# Separate state from ../terraform (apply after it). Everything here is cheap (~$0/month).
#   - S3 bucket that holds the fake client's Terraform remote state (badly configured)
#   - IRSA: OIDC provider for the lab EKS + a broad IAM role bound to a k8s service account
#   - an over-broad inline S3 policy on the EKS node role (makes pod -> IMDS -> node role -> S3 real)
#   - node IMDS hop limit 2 (pods can reach the node's IMDS)
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
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0"
    }
  }
}

variable "sandbox_account_id" {
  type = string
}
variable "aws_profile" {
  type    = string
  default = "roqy-sandbox-admin"
}
variable "region" {
  type    = string
  default = "eu-central-1"
}
variable "eks_cluster_name" {
  type    = string
  default = "roqy-lab-eks"
}
variable "k8s_namespace" {
  type    = string
  default = "roqy-lab-apps"
}

provider "aws" {
  region              = var.region
  profile             = var.aws_profile
  allowed_account_ids = [var.sandbox_account_id]
  default_tags {
    tags = {
      "roqy-lab"   = "true"
      "managed-by" = "terraform-roqy-vuln-lab-envelope"
      "warning"    = "VULNERABLE-BY-DESIGN-SANDBOX-ONLY"
    }
  }
}

data "aws_caller_identity" "me" {}
data "aws_iam_policy" "guard" {
  name = "roqy-lab-guard-deny-all"
}
data "aws_eks_cluster" "lab" {
  name = var.eks_cluster_name
}

resource "random_id" "sfx" {
  byte_length = 3
}

############################################################
# A1. Client Terraform remote-state bucket
#   PLANT tf-state-no-versioning   : versioning never enabled (one overwrite/delete = state gone)
#   PLANT tf-state-no-kms          : only the S3 default SSE-S3, no SSE-KMS, no TLS-only / encryption policy
#   PLANT tf-state-broad-read      : Principal * limited only by aws:PrincipalAccount = any principal in the
#                                    account (incl. every CI role, every dev) can read/overwrite state
#   (no-lock is a REPO plant: backend has neither dynamodb_table nor use_lockfile)
#   Not public: aws:PrincipalAccount makes the policy non-public, so account BPA does not interfere.
############################################################
resource "aws_s3_bucket" "client_state" {
  bucket        = "roqy-lab-client-tfstate-${random_id.sfx.hex}"
  force_destroy = true
  tags          = { "roqy-plant" = "tf-state-no-versioning tf-state-no-kms tf-state-broad-read" }
}

resource "aws_s3_bucket_ownership_controls" "client_state" {
  bucket = aws_s3_bucket.client_state.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_policy" "client_state_broad" {
  bucket = aws_s3_bucket.client_state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "EveryoneInTheCompanyCanUseState"
      Effect    = "Allow"
      Principal = "*"
      Action    = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
      Resource  = [aws_s3_bucket.client_state.arn, "${aws_s3_bucket.client_state.arn}/*"]
      Condition = { StringEquals = { "aws:PrincipalAccount" = data.aws_caller_identity.me.account_id } }
    }]
  })
}

############################################################
# B. IRSA: OIDC provider + broad role bound to roqy-lab-apps/billing-sa
#   PLANT k8s-irsa-broad-role : the SA's IAM role has s3:* + dynamodb:* + sqs:* on *
#   Guarded: deny-all permissions boundary (the broad policy is fully visible to the audit, inert if used).
############################################################
data "tls_certificate" "eks" {
  url = data.aws_eks_cluster.lab.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  url             = data.aws_eks_cluster.lab.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  tags            = { "roqy-plant" = "infra" }
}

locals {
  oidc_host = replace(data.aws_eks_cluster.lab.identity[0].oidc[0].issuer, "https://", "")
}

resource "aws_iam_role" "irsa_broad" {
  name                 = "roqy-lab-irsa-billing"
  permissions_boundary = data.aws_iam_policy.guard.arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${local.oidc_host}:sub" = "system:serviceaccount:${var.k8s_namespace}:billing-sa"
        "${local.oidc_host}:aud" = "sts.amazonaws.com"
      } }
    }]
  })
  tags = { "roqy-plant" = "k8s-irsa-broad-role" }
}

resource "aws_iam_role_policy" "irsa_broad" {
  name = "billing-needs-everything"
  role = aws_iam_role.irsa_broad.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:*", "dynamodb:*", "sqs:*"], Resource = "*" }]
  })
}

############################################################
# B/E. Node role gets broad S3 read (classic "the app on the node needs S3" shortcut)
#   PLANT k8s-node-role-s3 : roqy-lab-eks-node can read every bucket -> chain pod -> IMDS -> node role -> S3
#   NOT guarded (the node itself needs the role). Reachable only from pods on the lab node.
############################################################
resource "aws_iam_role_policy" "node_s3" {
  name = "nodes-read-all-buckets"
  role = "roqy-lab-eks-node"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject", "s3:ListBucket", "s3:ListAllMyBuckets"], Resource = "*" }]
  })
}

############################################################
# B. Node IMDS hop limit 2 (pods reach the node IMDS). Managed node group default is hop 1 on AL2023;
#   set out-of-band on the running node. Re-run apply (or scripts/apply-envelope.sh) after a node replacement.
############################################################
resource "terraform_data" "node_hop2" {
  triggers_replace = [timestamp()]
  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    command     = <<-EOT
      set -euo pipefail
      R="--region ${var.region} --profile ${var.aws_profile}"
      for i in $(aws ec2 describe-instances $R --filters Name=tag:eks:cluster-name,Values=${var.eks_cluster_name} Name=instance-state-name,Values=running --query 'Reservations[].Instances[].InstanceId' --output text); do
        aws ec2 modify-instance-metadata-options $R --instance-id "$i" --http-put-response-hop-limit 2 --http-endpoint enabled >/dev/null
        echo "node $i hop limit -> 2"
      done
    EOT
  }
}

output "client_state_bucket" {
  value = aws_s3_bucket.client_state.bucket
}
output "irsa_role_arn" {
  value = aws_iam_role.irsa_broad.arn
}
