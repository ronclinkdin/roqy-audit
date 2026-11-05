terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # no version constraint: next `init` on a new runner pulls whatever is latest
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

provider "aws" {
  region              = "eu-central-1"
  allowed_account_ids = ["856114194841"] # lab guard (the roqy sandbox); a real client repo would have its own id here
  default_tags {
    tags = { "roqy-lab" = "true", "managed-by" = "client-repo", "warning" = "VULNERABLE-BY-DESIGN-SANDBOX-ONLY" }
  }
}
