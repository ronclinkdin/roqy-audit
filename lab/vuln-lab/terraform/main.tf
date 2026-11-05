data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  sfx         = random_id.suffix.hex
  has_foreign = var.foreign_account_id != "" && var.foreign_account_id != data.aws_caller_identity.current.account_id
  # "External" principal used by cross-account plants. Falls back to the sandbox itself (safe).
  external_account = local.has_foreign ? var.foreign_account_id : data.aws_caller_identity.current.account_id
  boundary_arn     = var.guard_external_principals ? aws_iam_policy.guard_deny_all.arn : null

  # Every value below is FAKE. Formats look real on purpose so secret detectors fire.
  fake = {
    aws_key_id = "AKIAFAKEROQYLAB00000"
    aws_secret = "FAKEroqyLabSecretKeyDoNotUse0000000000000"
    stripe     = "sk_live_FAKE_roqy_lab_not_a_real_key_0000"
    db_pass    = "FAKE-Pa55w0rd-roqy-lab"
    gh_token   = "ghp_FAKEroqyLabNotARealToken000000000000"
  }
}

# Guard: deny-all permissions boundary. Attached to every lab principal that someone OUTSIDE the
# account could reach (OIDC role, cross-account role, console user/key, Cognito unauth role).
# The planted trust/permission policies are still fully visible to a read-only audit and must
# still be reported; the boundary only makes them inert if someone actually tries them.
resource "aws_iam_policy" "guard_deny_all" {
  name        = "roqy-lab-guard-deny-all"
  description = "roqy vuln-lab guard boundary: denies everything. Do not remove while the lab exists."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "RoqyLabGuardDenyAll"
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
  tags = { "roqy-plant" = "guard" }
}

# Small VPC so the lab never depends on a default VPC. No NAT gateway (cost).
resource "aws_vpc" "lab" {
  cidr_block           = "10.77.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = { Name = "roqy-lab-vpc", "roqy-plant" = "infra" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
  tags   = { Name = "roqy-lab-igw", "roqy-plant" = "infra" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = cidrsubnet(aws_vpc.lab.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags                    = { Name = "roqy-lab-public-${count.index}", "roqy-plant" = "infra" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
  tags = { Name = "roqy-lab-public-rt", "roqy-plant" = "infra" }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

module "second_region" {
  source = "./modules/second_region"
  count  = var.enable_second_region ? 1 : 0
  providers = {
    aws = aws.second
  }
  suffix = local.sfx
}
