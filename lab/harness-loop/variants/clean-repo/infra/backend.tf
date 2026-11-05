terraform {
  backend "s3" {
    bucket       = "acme-clean-tfstate"
    key          = "prod/terraform.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    kms_key_id   = "alias/tfstate"
    use_lockfile = true
  }
}
