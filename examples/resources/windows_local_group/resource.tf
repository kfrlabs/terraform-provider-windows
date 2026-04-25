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

# Create a custom Windows local group.
#
# The Terraform resource ID is set to the group SID, which Windows assigns
# at creation time and which remains stable across renames (ADR-LG-1).
# Changing the `name` attribute issues Rename-LocalGroup in place — no
# resource replacement occurs.
resource "windows_local_group" "app_admins" {
  name        = "AppAdmins"
  description = "Administrators of the AppSuite application stack."
}

# Expose the stable SID for use by windows_local_group_member (future).
output "app_admins_sid" {
  value       = windows_local_group.app_admins.sid
  description = "SID of the AppAdmins group — stable across renames."
}
