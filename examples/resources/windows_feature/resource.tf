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

# Minimal example: install IIS (Web-Server role).
resource "windows_feature" "iis" {
  name = "Web-Server"
}

# Advanced example: install AD DS with all sub-features and management tools,
# scheduling a detached host reboot ~60s after the operation when a reboot is
# required (restart = true only takes effect when RestartNeeded is reported).
# The reboot is per-resource: enable restart=true on at most one resource per
# apply (or apply reboot-requiring features last/separately), since a later
# in-flight SSH session on the same host can still be dropped by the reboot.
resource "windows_feature" "ad_ds" {
  name                     = "AD-Domain-Services"
  include_sub_features     = true
  include_management_tools = true
  restart                  = true
}

# Offline-source example: install .NET 3.5 from an SxS share when the payload
# has been removed from the live image (install_state = "Removed").
resource "windows_feature" "netfx3" {
  name   = "NET-Framework-Core"
  source = "\\\\fileserver\\share\\sources\\sxs"
}
