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

# Read-only lookup of one interface's DNS client settings.
data "windows_dns_client" "secondary" {
  interface_alias = "Ethernet 2"
}

output "dns_static_ipv4" {
  value       = data.windows_dns_client.secondary.ipv4_server_addresses
  description = "Statically configured IPv4 DNS servers ([] when the family is automatic)."
}

output "dns_effective_ipv4" {
  value       = data.windows_dns_client.secondary.effective_ipv4
  description = "Live IPv4 DNS servers (static plus DHCP-provided)."
}
