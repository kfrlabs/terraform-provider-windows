terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host      = var.windows_host
  username  = var.windows_username
  password  = var.windows_password
  auth_type = "ntlm"
}

# Singleton — no lookup keys required.
data "windows_hostname" "current" {}

output "current_name" {
  value = data.windows_hostname.current.current_name
}

output "machine_id" {
  value = data.windows_hostname.current.machine_id
}
