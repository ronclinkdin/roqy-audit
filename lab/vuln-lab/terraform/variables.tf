variable "sandbox_account_id" {
  description = "12-digit ID of the EMPTY sandbox account. Terraform refuses to touch any other account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.sandbox_account_id))
    error_message = "sandbox_account_id must be a 12-digit AWS account ID."
  }
}

variable "aws_profile" {
  description = "AWS CLI profile of the sandbox ADMIN (used by terraform and by the few local-exec aws CLI calls)."
  type        = string
  default     = "roqy-sandbox-admin"
}

variable "region" {
  description = "Primary lab region."
  type        = string
  default     = "eu-central-1"
}

variable "second_region" {
  description = "Second region, to verify that the audit loops over regions."
  type        = string
  default     = "us-east-1"
}

variable "enable_second_region" {
  description = "Plant a small set of weaknesses in var.second_region (free resources only)."
  type        = bool
  default     = true
}

variable "allow_public" {
  description = <<-EOT
    DANGER. false (default) = nothing is reachable from the internet beyond the documented,
    harmless endpoints (API Gateway hello route, SNS/SQS/Lambda policies with Principal *).
    true = additionally makes resources TRULY public: S3 public read+write bucket policy,
    public EBS snapshot, public AMI, Lambda Function URL with AuthType NONE, public ECR pull,
    and an IAM trust policy with Principal "*". Only flip this for a short, supervised run,
    and run `terraform apply -var allow_public=false` (or destroy) right after.
    Account-level S3 Block Public Access is NEVER changed by this lab; if it is on, the
    public bucket policy apply will fail with AccessDenied - that is expected and safe.
  EOT
  type        = bool
  default     = false
}

variable "foreign_account_id" {
  description = "A SECOND AWS account that Ron owns (or empty). Used as the 'external' principal for cross-account plants (KMS, S3, snapshot share, role trust). Empty = sandbox's own account is used and cross-account-only plants are skipped."
  type        = string
  default     = ""
  validation {
    condition     = var.foreign_account_id == "" || can(regex("^[0-9]{12}$", var.foreign_account_id))
    error_message = "foreign_account_id must be empty or a 12-digit AWS account ID."
  }
}

variable "guard_external_principals" {
  description = "Attach a deny-all permissions boundary to every lab principal that is reachable from outside the account (GitHub OIDC role, cross-account role, console user + key, Cognito unauth role). Keep true."
  type        = bool
  default     = true
}

variable "instance_state" {
  description = "IMDSv1 EC2 instance: none = not created (SG/launch template still created), stopped = created then stopped (~$0.70/mo EBS), running = t4g.nano running with a public IPv4 (~$7/mo)."
  type        = string
  default     = "running"
  validation {
    condition     = contains(["none", "stopped", "running"], var.instance_state)
    error_message = "instance_state must be none, stopped or running."
  }
}

variable "schedule_kms_deletion" {
  description = "Schedule the second KMS key for deletion (plant kms-pending-deletion). Uses local aws CLI."
  type        = bool
  default     = true
}

variable "create_weak_trail" {
  description = "false (default) = no CloudTrail at all (absence plant). true = a single-region trail with log file validation off."
  type        = bool
  default     = false
}

variable "dns_zone_type" {
  description = "private (default, no takeover risk) or public. public requires dns_domain to be a domain Ron controls AND NOT delegated, otherwise the dangling CNAMEs are really takeover-able."
  type        = string
  default     = "private"
  validation {
    condition     = contains(["private", "public", "none"], var.dns_zone_type)
    error_message = "dns_zone_type must be private, public or none."
  }
}

variable "dns_domain" {
  description = "Zone name for the dangling-DNS plant."
  type        = string
  default     = "roqy-lab.internal"
}

variable "enable_secrets_manager" {
  description = "Secrets Manager secret without rotation (~$0.40/mo)."
  type        = bool
  default     = false
}

variable "codebuild_webhook_repo_url" {
  description = "Optional https GitHub repo URL (a throwaway repo Ron owns). If set, a CodeBuild project with an UNANCHORED webhook ACTOR_ACCOUNT_ID filter is created. Requires GitHub source credentials already imported in the sandbox (aws codebuild import-source-credentials). Empty = skipped."
  type        = string
  default     = ""
}

variable "enable_rds" {
  description = "publicly_accessible, unencrypted, old-but-supported-engine RDS db.t4g.micro (~$18/mo). No deletion protection, no final snapshot."
  type        = bool
  default     = true
}

variable "rds_engine_version" {
  description = "Oldest PostgreSQL major still in STANDARD support (14 ends Feb 2027). 13 or older = RDS Extended Support charges per vCPU-hour."
  type        = string
  default     = "14"
}

variable "enable_eks" {
  description = "EKS: public endpoint 0.0.0.0/0, creator-admin bootstrap, broad cluster-admin access entry, 1 small node in a public subnet (~$95/mo)."
  type        = bool
  default     = true
}

variable "eks_version" {
  description = "null = AWS current default (standard support). Set an old version (e.g. 1.30) to plant eks-old-version, BUT extended support costs +$0.50/h (~$365/mo)."
  type        = string
  default     = null
}

variable "eks_node_instance_type" {
  description = "Single managed node (ARM, AL2023)."
  type        = string
  default     = "t4g.small"
}

variable "quarantine_policy_arn" {
  description = "AWS managed policy AWS attaches to a key it found leaked. Plant simulates that state."
  type        = string
  default     = "arn:aws:iam::aws:policy/AWSCompromisedKeyQuarantineV2"
}
