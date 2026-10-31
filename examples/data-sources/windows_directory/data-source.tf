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

# Look up the observed state of an existing directory.
data "windows_directory" "logs" {
  path = "C:\\data\\logs"
}

output "logs_item_count" {
  value = data.windows_directory.logs.item_count
}

output "logs_last_write_time" {
  value = data.windows_directory.logs.last_write_time
}
