terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
  }
}

variable "suffix" {
  type = string
}

resource "aws_vpc" "r2" {
  cidr_block = "10.78.0.0/16"
  tags       = { Name = "roqy-lab-r2-vpc", "roqy-plant" = "infra" }
}

resource "aws_security_group" "r2_open" {
  name        = "roqy-lab-r2-forgotten-ssh"
  description = "PLANT r2-open-sg: forgotten SG in a region nobody looks at"
  vpc_id      = aws_vpc.r2.id
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  tags = { Name = "roqy-lab-r2-forgotten-ssh", "roqy-plant" = "r2-open-sg" }
}

resource "aws_ssm_parameter" "r2_plain" {
  name  = "/roqy-lab-r2/legacy/api_secret_key"
  type  = "String"
  value = "FAKE-roqy-lab-r2-secret-${var.suffix}"
  tags  = { "roqy-plant" = "r2-ssm-plaintext" }
}

output "sg_id" {
  value = aws_security_group.r2_open.id
}
