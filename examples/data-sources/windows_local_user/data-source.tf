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

# Look up a local user account by name.
data "windows_local_user" "svc_app" {
  name = "svc-app"
}

# Alternatively, look up by SID.
data "windows_local_user" "by_sid" {
  sid = "S-1-5-21-123456789-1001"
}

output "svc_app_enabled" {
  value = data.windows_local_user.svc_app.enabled
}

output "svc_app_sid" {
  value = data.windows_local_user.svc_app.sid
}
