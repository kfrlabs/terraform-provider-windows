terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.0"
    }
  }
}

provider "windows" {
  host                     = var.windows_host
  port                     = var.windows_port
  username                 = var.windows_username
  insecure_ignore_host_key = var.windows_insecure_ignore_host_key
}
