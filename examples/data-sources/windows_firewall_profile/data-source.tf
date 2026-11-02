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

# Read the observed state of the Public profile (read-only, no lifecycle).
data "windows_firewall_profile" "public" {
  name = "Public"
}

output "public_inbound_action" {
  value = data.windows_firewall_profile.public.default_inbound_action
}

output "public_enabled" {
  value = data.windows_firewall_profile.public.enabled
}

# Inspect a profile managed by the windows_firewall_profile resource in the
# same configuration. The data source returns the observed live state,
# including GPO-managed NotConfigured tri-states (reported as null).
data "windows_firewall_profile" "managed" {
  name = windows_firewall_profile.private.name
}
