variable "windows_host" {
  description = "The hostname or IP address of the Windows server"
  type        = string
  default     = "windows-server.example.com"
}

variable "windows_username" {
  description = "The username for SSH authentication"
  type        = string
  default     = "Administrator"
}

variable "windows_password" {
  description = "The password for SSH authentication"
  type        = string
  sensitive   = true
}

variable "windows_key_path" {
  description = "Path to the SSH private key"
  type        = string
  default     = "~/.ssh/id_rsa"
}

variable "enable_pool" {
  description = "Enable SSH connection pooling"
  type        = bool
  default     = true
}

variable "pool_max_idle" {
  description = "Maximum number of idle connections in the pool"
  type        = number
  default     = 5
}

variable "pool_max_active" {
  description = "Maximum number of active connections"
  type        = number
  default     = 10
}