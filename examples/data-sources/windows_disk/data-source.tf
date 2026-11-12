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

# Look up a disk by its stable UniqueId without managing it.
data "windows_disk" "data" {
  unique_id = "SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK&REV_1.0"
}

output "disk_size_bytes" {
  value = data.windows_disk.data.size_bytes
}
