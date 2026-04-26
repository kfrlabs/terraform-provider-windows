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

# Look up the IIS web server feature state.
data "windows_feature" "iis" {
  name = "Web-Server"
}

output "iis_installed" {
  value = data.windows_feature.iis.installed
}

output "iis_install_state" {
  value = data.windows_feature.iis.install_state
}
