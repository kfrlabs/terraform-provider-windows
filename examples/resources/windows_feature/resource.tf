terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host      = var.windows_host
  username  = var.windows_username
  password  = var.windows_password
  auth_type = "ntlm"
}

# Minimal example: install IIS (Web-Server role).
resource "windows_feature" "iis" {
  name = "Web-Server"
}

# Advanced example: install AD DS with all sub-features and management tools,
# allowing the cmdlet to reboot automatically when needed.
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
