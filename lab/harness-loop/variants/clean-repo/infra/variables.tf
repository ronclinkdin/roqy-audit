variable "db_password_secret_arn" {
  description = "ARN only; the value lives in Secrets Manager"
  type        = string
}
variable "environment" {
  type    = string
  default = "prod"
}
