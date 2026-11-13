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

# Read the observed state of the Default Web Site (read-only, no lifecycle).
data "windows_iis_site" "default" {
  name = "Default Web Site"
}

output "default_physical_path" {
  value = data.windows_iis_site.default.physical_path
}

output "default_state" {
  value = data.windows_iis_site.default.state
}

# Inspect a site managed by the windows_iis_site resource in the same
# configuration. The data source returns the observed live state
# (connection timeout in whole seconds; bindings as the read-only view).
data "windows_iis_site" "managed" {
  name = windows_iis_site.web.name
}
