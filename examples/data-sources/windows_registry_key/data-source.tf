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

# Enumerate a key for drift detection without purge.
data "windows_registry_key" "app" {
  hive = "HKLM"
  path = "SOFTWARE\\MyApp"
}

output "registry_value_names" {
  value = data.windows_registry_key.app.value_names
}

output "registry_values_summary" {
  value = data.windows_registry_key.app.values
}
