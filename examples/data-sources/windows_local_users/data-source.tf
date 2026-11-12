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

# Every enabled local user account on the target host.
data "windows_local_users" "enabled" {
  enabled = true
}

output "enabled_user_names" {
  value       = data.windows_local_users.enabled.names
  description = "SAM account names of every enabled local user on the host."
}

check "no_unexpected_admins" {
  assert {
    condition     = alltrue([for u in data.windows_local_users.enabled.users : u.is_builtin || startswith(u.name, "svc-")])
    error_message = "Unexpected enabled local user found; review the account inventory."
  }
}
