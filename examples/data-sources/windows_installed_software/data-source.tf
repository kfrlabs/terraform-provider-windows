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

# Full installed-software inventory of the target host.
data "windows_installed_software" "all" {
  # No filters: full inventory.
}

# Only the .NET runtimes (updates and system components included).
data "windows_installed_software" "dotnet" {
  name_regex                = "Microsoft .NET.*"
  include_updates           = true
  include_system_components = true
}

output "installed_software_names" {
  value       = [for p in data.windows_installed_software.all.packages : p.name]
  description = "Display names of every installed package on the host."
}

output "dotnet_inventory" {
  value = [
    for p in data.windows_installed_software.dotnet.packages : {
      name         = p.name
      version      = p.version
      product_code = p.product_code
      scope        = p.scope
    }
  ]
  description = "Installed .NET packages with their versions and product codes."
}

output "skipped_entries" {
  value       = data.windows_installed_software.all.skipped_entries
  description = "Registry keys skipped because their values were unreadable."
}
