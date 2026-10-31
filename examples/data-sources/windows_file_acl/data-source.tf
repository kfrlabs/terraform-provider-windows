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

# Look up the observed security descriptor of an existing file.
data "windows_file_acl" "app_conf" {
  path = "C:\\data\\app.conf"
}

output "app_conf_owner_sid" {
  value = data.windows_file_acl.app_conf.owner_sid
}

output "app_conf_sddl" {
  value = data.windows_file_acl.app_conf.sddl
}
