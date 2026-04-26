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

# Look up the built-in Administrators group by name.
data "windows_local_group" "admins" {
  name = "Administrators"
}

# Alternatively, look up by SID.
data "windows_local_group" "remote_desktop_users" {
  sid = "S-1-5-32-555"
}

output "admins_sid" {
  value = data.windows_local_group.admins.sid
}

output "admins_description" {
  value = data.windows_local_group.admins.description
}
