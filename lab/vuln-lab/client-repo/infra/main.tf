# Naming/tag module straight from git, no ?ref= pin: whoever controls that repo's default branch
# controls what runs inside our next `terraform apply`.
module "label" {
  source    = "git::https://github.com/cloudposse/terraform-null-label.git"
  namespace = "roqy"
  stage     = "prod"
  name      = "client-web"
}

# Latest "al2023" AMI from ANY publisher: no `owners`, so a look-alike community AMI can win.
data "aws_ami" "al2023" {
  most_recent = true
  # added when provider v6 started refusing this lookup ("Most Recent Image Not Filtered") - silenced, not fixed
  allow_unsafe_filter = true
  filter {
    name   = "name"
    values = ["al2023-ami-2023*-arm64"]
  }
}

data "aws_vpc" "lab" {
  filter {
    name   = "tag:Name"
    values = ["roqy-lab-vpc"]
  }
}

resource "aws_security_group" "web" {
  name        = "roqy-lab-client-web"
  description = "client web tier (managed by terraform)"
  vpc_id      = data.aws_vpc.lab.id
  ingress {
    description = "https from inside the VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.77.0.0/16"]
  }
  tags = merge(module.label.tags, { Name = "roqy-lab-client-web", Owner = "platform-team", Env = "prod" })
}

resource "aws_launch_template" "web" {
  name                   = "roqy-lab-client-web-lt"
  image_id               = data.aws_ami.al2023.id
  instance_type          = "t4g.micro"
  vpc_security_group_ids = [aws_security_group.web.id]
  metadata_options {
    http_tokens = "required"
  }
}

# The DB password goes through Terraform, so it lands in PLAINTEXT in the remote state,
# regardless of SecureString / sensitive = true.
resource "aws_ssm_parameter" "db_password" {
  name  = "/roqy-lab-client/prod/legacy-db/password"
  type  = "SecureString"
  value = var.db_password
}

output "db_url" {
  value     = "postgres://app:${var.db_password}@${var.db_host}:5432/app"
  sensitive = true
}
