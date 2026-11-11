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

# Read the observed state of the DefaultAppPool (read-only, no lifecycle).
data "windows_iis_app_pool" "default" {
  name = "DefaultAppPool"
}

output "default_runtime" {
  value = data.windows_iis_app_pool.default.managed_runtime_version
}

output "default_state" {
  value = data.windows_iis_app_pool.default.state
}

# Inspect a pool managed by the windows_iis_app_pool resource in the same
# configuration. The data source returns the observed live state (durations
# as whole minutes, cpu.limit thousandths as whole percent).
data "windows_iis_app_pool" "managed" {
  name = windows_iis_app_pool.api.name
}
