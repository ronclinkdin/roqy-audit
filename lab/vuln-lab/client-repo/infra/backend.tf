# Remote state for prod. Shared bucket, everyone in the company can use it.
terraform {
  backend "s3" {
    bucket  = "roqy-lab-client-tfstate-40e604"
    key     = "prod/terraform.tfstate"
    region  = "eu-central-1"
    encrypt = false
    # no dynamodb_table, no use_lockfile: two applies at once corrupt state
  }
}
