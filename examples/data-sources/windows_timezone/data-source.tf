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
data "windows_timezone" "current" {}

output "timezone_id" {
  value = data.windows_timezone.current.timezone_id
}

output "current_utc_offset" {
  value = data.windows_timezone.current.current_utc_offset
}

output "id" {
  value = data.windows_timezone.current.id
}
