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

# Look up the observed metadata of an existing file (metadata only: no content).
data "windows_file" "app_conf" {
  path = "C:\\data\\app.conf"
}

output "app_conf_sha256" {
  value = data.windows_file.app_conf.content_sha256
}

output "app_conf_size_bytes" {
  value = data.windows_file.app_conf.size_bytes
}
