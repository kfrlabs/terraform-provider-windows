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

# Look up an installed MSI package by its ProductCode GUID.
data "windows_legacy_package" "seven_zip" {
  product_id = "{23170F69-40C1-2702-2502-000001000000}"
}

output "seven_zip_installed" {
  value = data.windows_legacy_package.seven_zip.installed
}

output "seven_zip_version" {
  value = data.windows_legacy_package.seven_zip.installed_version
}
