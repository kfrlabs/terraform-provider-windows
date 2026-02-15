variable "service_account_password" {
  description = "Password for the service account"
  type        = string
  sensitive   = true
}

variable "existing_user_password" {
  description = "Password for the existing user"
  type        = string
  sensitive   = true
}

variable "developer_passwords" {
  description = "Map of developer usernames to passwords"
  type        = map(string)
  sensitive   = true
  default = {
    dev1 = "Dev1P@ss!"
    dev2 = "Dev2P@ss!"
    dev3 = "Dev3P@ss!"
  }
}

variable "backup_admin_password" {
  description = "Password for backup administrator"
  type        = string
  sensitive   = true
}

variable "sql_service_password" {
  description = "Password for SQL Server service account"
  type        = string
  sensitive   = true
}

variable "iis_password" {
  description = "Password for IIS application pool identity"
  type        = string
  sensitive   = true
}