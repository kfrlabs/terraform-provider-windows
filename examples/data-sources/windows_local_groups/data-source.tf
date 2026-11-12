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

# Every non-built-in local group on the target host, with membership.
data "windows_local_groups" "custom" {
  include_builtin = false
  include_members = true
}

output "custom_group_names" {
  value       = data.windows_local_groups.custom.names
  description = "Names of every non-built-in local group on the host."
}

check "no_unexpected_admins" {
  assert {
    condition     = alltrue([for g in data.windows_local_groups.custom.groups : g.is_builtin || startswith(g.name, "svc-")])
    error_message = "Unexpected non-built-in local group found; review the group inventory."
  }
}
