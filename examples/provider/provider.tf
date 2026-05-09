terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.0"
    }
  }
}

provider "windows" {
  host      = var.windows_host
  username  = var.windows_username
  password  = var.windows_password
  auth_type = "ntlm"
}
