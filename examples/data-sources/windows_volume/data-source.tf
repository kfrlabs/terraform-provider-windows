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

# Look up a volume by its stable UniqueId without managing it.
data "windows_volume" "data" {
  unique_id = "\\\\?\\Volume{11111111-2222-3333-4444-555555555555}\\"
}

output "volume_label" {
  value = data.windows_volume.data.file_system_label
}
