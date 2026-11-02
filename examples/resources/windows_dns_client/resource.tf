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

# Static DNS servers on a secondary NIC (the management NIC keeps its own
# resolvers). Documentation ranges only (RFC 5737 / RFC 3849). Omitting a
# family leaves it unmanaged; an empty list resets it to automatic (DHCP).
resource "windows_dns_client" "secondary" {
  interface_alias       = "Ethernet 2"
  ipv4_server_addresses = ["192.0.2.53", "198.51.100.53"] # documentation range, RFC 5737
  ipv6_server_addresses = ["2001:db8::53"]                # documentation range, RFC 3849

  connection_specific_suffix       = "corp.example.com" # documentation range, RFC 2606
  register_this_connection_address = true
  use_suffix_when_registering      = true

  # Reset the managed families to automatic (DHCP) on destroy.
  reset_on_destroy = true

  # Bound every remote operation explicitly. Without this block each operation
  # defaults to 10 minutes; a stalled PowerShell/SSH session then surfaces a
  # timeout diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "10m"
    read   = "5m"
    update = "10m"
    delete = "10m"
  }
}

output "dns_effective_ipv4" {
  value       = windows_dns_client.secondary.effective_ipv4
  description = "Live IPv4 DNS servers (static plus DHCP-provided)."
}
