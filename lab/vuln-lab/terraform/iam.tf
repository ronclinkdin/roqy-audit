############################################################
# c7  GitHub Actions OIDC trust WITHOUT a `sub` condition
############################################################
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
  # AWS no longer validates thumbprints for this IdP, but the API still wants one.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
  tags            = { "roqy-plant" = "iam-github-oidc-no-sub" }
}

resource "aws_iam_role" "github_oidc_no_sub" {
  name                 = "roqy-lab-github-deploy"
  description          = "PLANT iam-github-oidc-no-sub: any GitHub repo in the world can assume this (sub = repo:*). Guarded by deny-all boundary."
  permissions_boundary = local.boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        # AWS (since 2025) rejects a GitHub OIDC trust with NO sub condition at CreateRole time.
        # It still accepts a sub wildcard that matches every repo on GitHub, which is the same hole:
        StringLike = { "token.actions.githubusercontent.com:sub" = "repo:*" }
        # SHOULD BE: StringEquals sub = "repo:<org>/<repo>:ref:refs/heads/main"
      }
    }]
  })
  tags = { "roqy-plant" = "iam-github-oidc-no-sub" }
}

resource "aws_iam_role_policy_attachment" "github_oidc_poweruser" {
  role       = aws_iam_role.github_oidc_no_sub.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

############################################################
# c8  Cross-account trust without ExternalId (confused deputy)
############################################################
resource "aws_iam_role" "vendor_no_externalid" {
  name                 = "roqy-lab-vendor-integration"
  description          = "PLANT iam-cross-account-no-externalid: trusts an external account root with no sts:ExternalId. Guarded."
  permissions_boundary = local.boundary_arn
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Sid       = "VendorNoExternalId"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${local.external_account}:root" }
        Action    = "sts:AssumeRole"
      }],
      var.allow_public ? [{
        Sid       = "WildcardPrincipalPublicPlant"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "sts:AssumeRole"
      }] : []
    )
  })
  tags = { "roqy-plant" = var.allow_public ? "iam-cross-account-no-externalid iam-trust-wildcard-principal" : "iam-cross-account-no-externalid" }
}

resource "aws_iam_role_policy_attachment" "vendor_readonly" {
  role       = aws_iam_role.vendor_no_externalid.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

############################################################
# c17 + c1  Human user: console password, no MFA, unused access key
############################################################
resource "aws_iam_user" "console_no_mfa" {
  name                 = "roqy-lab-console-user"
  force_destroy        = true
  permissions_boundary = local.boundary_arn
  tags                 = { "roqy-plant" = "iam-console-no-mfa iam-user-unused-key" }
}

resource "aws_iam_user_login_profile" "console_no_mfa" {
  user                    = aws_iam_user.console_no_mfa.name
  password_length         = 32
  password_reset_required = false
}

resource "aws_iam_access_key" "unused" {
  user = aws_iam_user.console_no_mfa.name
}

resource "aws_iam_user_policy_attachment" "console_admin" {
  user       = aws_iam_user.console_no_mfa.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

############################################################
# c1  User carrying the AWS "compromised key" quarantine policy
############################################################
resource "aws_iam_user" "quarantined" {
  name          = "roqy-lab-leaked-ci-user"
  force_destroy = true
  tags          = { "roqy-plant" = "iam-quarantined-user" }
}

resource "aws_iam_user_policy_attachment" "quarantined" {
  user       = aws_iam_user.quarantined.name
  policy_arn = var.quarantine_policy_arn
}

############################################################
# c3  Privilege escalation primitives (user has NO credentials -> not reachable from outside)
############################################################
resource "aws_iam_user" "privesc" {
  name          = "roqy-lab-intern"
  force_destroy = true
  tags          = { "roqy-plant" = "iam-privesc-user" }
}

resource "aws_iam_user_policy" "privesc" {
  name = "roqy-lab-intern-dev"
  user = aws_iam_user.privesc.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PolicyVersionTakeover"
        Effect   = "Allow"
        Action   = ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"]
        Resource = "*"
      },
      {
        Sid      = "PassRoleToLambda"
        Effect   = "Allow"
        Action   = ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction", "lambda:UpdateFunctionCode"]
        Resource = "*"
      },
      {
        Sid      = "TrustRewrite"
        Effect   = "Allow"
        Action   = ["iam:UpdateAssumeRolePolicy", "iam:AttachUserPolicy", "iam:PutRolePolicy", "iam:CreateAccessKey", "iam:CreateLoginProfile"]
        Resource = "*"
      },
      {
        Sid      = "SsmShell"
        Effect   = "Allow"
        Action   = ["ssm:SendCommand"]
        Resource = "*"
      }
    ]
  })
}

############################################################
# c3  Wildcard admin inline policy on a workload role
############################################################
resource "aws_iam_role" "wildcard_admin" {
  name        = "roqy-lab-app-server"
  description = "PLANT iam-wildcard-admin-role: EC2 role with Action * Resource * inline."
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { "roqy-plant" = "iam-wildcard-admin-role" }
}

resource "aws_iam_role_policy" "wildcard_admin" {
  name = "everything"
  role = aws_iam_role.wildcard_admin.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

resource "aws_iam_instance_profile" "wildcard_admin" {
  name = "roqy-lab-app-server"
  role = aws_iam_role.wildcard_admin.name
}

############################################################
# c3  NotAction "everything except IAM" (still near-admin)
############################################################
resource "aws_iam_policy" "notaction" {
  name        = "roqy-lab-everything-but-iam"
  description = "PLANT iam-notaction-policy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", NotAction = ["iam:*", "organizations:*"], Resource = "*" }]
  })
  tags = { "roqy-plant" = "iam-notaction-policy" }
}

resource "aws_iam_role" "notaction" {
  name = "roqy-lab-data-team"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::${local.account_id}:root" }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
  tags = { "roqy-plant" = "iam-notaction-policy" }
}

resource "aws_iam_role_policy_attachment" "notaction" {
  role       = aws_iam_role.notaction.name
  policy_arn = aws_iam_policy.notaction.arn
}

# NOTE (absence plant iam-no-password-policy): this lab deliberately does NOT create
# aws_iam_account_password_policy. If the sandbox already has one, that plant is not active.
