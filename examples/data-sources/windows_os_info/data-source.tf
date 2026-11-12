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
data "windows_os_info" "current" {}

output "product_name" {
  value = data.windows_os_info.current.product_name
}

output "full_build" {
  value = data.windows_os_info.current.full_build
}

# Example: only manage a resource on Server Core hosts.
resource "terraform_data" "core_only" {
  count = data.windows_os_info.current.is_server_core ? 1 : 0
}

# Requires Terraform 1.5+ for check blocks.
check "supported_os" {
  assert {
    condition     = contains(["ServerStandard", "ServerDatacenter"], data.windows_os_info.current.edition_id)
    error_message = "Unsupported OS edition: ${data.windows_os_info.current.edition_id}."
  }
}
