terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host     = var.windows_host
  username = var.windows_username
  password = var.windows_password
}

# Singleton — no lookup keys required.
data "windows_ntp" "current" {}

output "type" {
  value = data.windows_ntp.current.type
}

output "servers" {
  value = data.windows_ntp.current.servers
}

output "current_source" {
  value = data.windows_ntp.current.current_source
}

output "id" {
  value = data.windows_ntp.current.id
}
