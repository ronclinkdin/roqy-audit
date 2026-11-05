output "lab_summary" {
  value = {
    account_id         = local.account_id
    region             = var.region
    second_region      = var.enable_second_region ? var.second_region : "disabled"
    allow_public       = var.allow_public
    cross_account_used = local.has_foreign
    instance_state     = var.instance_state
    rds                = var.enable_rds
    eks                = var.enable_eks
    api_endpoint       = aws_apigatewayv2_api.http.api_endpoint
  }
}

output "console_user_password" {
  description = "Password of the planted no-MFA console user (inert: deny-all boundary). Never needed for the audit."
  value       = aws_iam_user_login_profile.console_no_mfa.password
  sensitive   = true
}

output "unused_access_key_id" {
  description = "ID (not secret) of the planted unused access key."
  value       = aws_iam_access_key.unused.id
}
