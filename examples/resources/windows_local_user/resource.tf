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

# ---------------------------------------------------------------------------
# Example 1 — minimal local service account
#
# The Terraform resource ID (id) is set to the user SID assigned by Windows
# at creation time. The SID remains stable even if the name is later changed
# in HCL (Rename-LocalUser is called in place — no resource replacement).
# ---------------------------------------------------------------------------
resource "windows_local_user" "svc_backup" {
  name     = "svc-backup"
  password = var.svc_backup_password
}

output "svc_backup_sid" {
  value       = windows_local_user.svc_backup.sid
  description = "SID of svc-backup — stable across renames."
  sensitive   = false
}

# ---------------------------------------------------------------------------
# Example 2 — full triptyque: windows_local_user + windows_local_group +
#             windows_local_group_member
#
# Shows the recommended pattern for assembling the three companion resources:
#   1. windows_local_user   — the account itself
#   2. windows_local_group  — a custom group to grant privilege
#   3. windows_local_group_member — grants the user membership in the group
#
# Password is passed via a sensitive variable (never hard-coded).
# password_wo_version controls rotation: bump the counter to force
# Set-LocalUser -Password even if the password value has not changed.
# ---------------------------------------------------------------------------

variable "svc_app_password" {
  type        = string
  sensitive   = true
  description = "Password for the svc-app local user account."
}

# 1. Local user account
resource "windows_local_user" "svc_app" {
  name                         = "svc-app"
  full_name                    = "App Service Account"
  description                  = "Runs the AppSuite service."
  password                     = var.svc_app_password
  password_wo_version          = 1
  enabled                      = true
  password_never_expires       = true
  user_may_not_change_password = true
  account_never_expires        = true
}

# 2. Custom local group
resource "windows_local_group" "app_operators" {
  name        = "AppOperators"
  description = "Operators allowed to run AppSuite."
}

# 3. Grant svc-app membership in AppOperators (non-authoritative: out-of-band
#    memberships in AppOperators are left undisturbed)
resource "windows_local_group_member" "app_operators_svc_app" {
  group  = windows_local_group.app_operators.name
  member = windows_local_user.svc_app.name
}

# Expose computed attributes for downstream resources.
output "svc_app_sid" {
  value       = windows_local_user.svc_app.sid
  description = "SID of svc-app — stable across renames."
  sensitive   = false
}
