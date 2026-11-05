variable "db_password" {
  description = "legacy-db app user password"
  type        = string
  sensitive   = true
  default     = "FAKE-ClientRepo-Pa55w0rd-roqy-lab" # FAKE lab value; the plant is "a real password default in git"
}

variable "db_host" {
  type    = string
  default = "roqy-lab-legacy-db"
}
