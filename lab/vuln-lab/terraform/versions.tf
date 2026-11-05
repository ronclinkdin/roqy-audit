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
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.4.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  # Hard stop: refuse to run against any account that is not the declared sandbox.
  allowed_account_ids = [var.sandbox_account_id]

  default_tags {
    tags = {
      "roqy-lab"   = "true"
      "managed-by" = "terraform-roqy-vuln-lab"
      "warning"    = "VULNERABLE-BY-DESIGN-SANDBOX-ONLY"
    }
  }
}

provider "aws" {
  alias   = "second"
  region  = var.second_region
  profile = var.aws_profile

  allowed_account_ids = [var.sandbox_account_id]

  default_tags {
    tags = {
      "roqy-lab"   = "true"
      "managed-by" = "terraform-roqy-vuln-lab"
      "warning"    = "VULNERABLE-BY-DESIGN-SANDBOX-ONLY"
    }
  }
}
