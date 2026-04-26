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

# Look up the Windows Update service by its short name.
data "windows_service" "wuauserv" {
  name = "wuauserv"
}

output "wuauserv_display_name" {
  value = data.windows_service.wuauserv.display_name
}

output "wuauserv_start_type" {
  value = data.windows_service.wuauserv.start_type
}

output "wuauserv_current_status" {
  value = data.windows_service.wuauserv.current_status
}
