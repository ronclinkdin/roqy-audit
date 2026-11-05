module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.13.0"
  name    = "clean"
}
module "internal" {
  source = "git::https://github.com/acme/tf-modules.git//network?ref=4f1c2d3e5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"
}
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}
resource "aws_db_instance" "app" {
  identifier                  = "clean-app"
  engine                      = "postgres"
  instance_class              = "db.t4g.micro"
  allocated_storage           = 20
  username                    = "app"
  manage_master_user_password = true
  storage_encrypted           = true
  deletion_protection         = true
  backup_retention_period     = 7
  publicly_accessible         = false
}
resource "aws_ssm_parameter" "feature_flags" {
  name  = "/clean/feature-flags"
  type  = "String"
  value = "{\"beta\":false}"
}
