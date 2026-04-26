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

# Look up a specific member of the Administrators group by name.
data "windows_local_group_member" "admin_user" {
  group_name  = "Administrators"
  member_name = "Administrator"
}

output "admin_user_sid" {
  value = data.windows_local_group_member.admin_user.member_sid
}

output "admin_user_principal_source" {
  value = data.windows_local_group_member.admin_user.member_principal_source
}
