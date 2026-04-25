terraform {
  required_providers {
    windows = {
      source  = "ecritel/windows"
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

# Add a domain user to the built-in Administrators group.
#
# The composite resource ID is "<group_sid>/<member_sid>" — both SIDs are
# stable across renames so a group or account rename does not force
# resource replacement (ADR-LGM-1).
#
# Non-authoritative: any out-of-band memberships in the group are left
# undisturbed; only this specific (group, member) pair is managed (EC-12).
resource "windows_local_group_member" "admin_jdoe" {
  group  = "Administrators"
  member = "DOMAIN\\jdoe"
}

# Add a local account to a custom group created by windows_local_group.
#
# Using windows_local_group.app_admins.name as the group value ensures the
# dependency is declared explicitly to Terraform.
resource "windows_local_group" "app_admins" {
  name        = "AppAdmins"
  description = "Administrators of the AppSuite application stack."
}

resource "windows_local_group_member" "app_admins_alice" {
  group  = windows_local_group.app_admins.name
  member = "alice@corp.example.com"
}

# Expose computed attributes for use by downstream resources.
output "admin_jdoe_member_sid" {
  value       = windows_local_group_member.admin_jdoe.member_sid
  description = "Resolved SID of DOMAIN\\jdoe — stable across account renames."
}
