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

# Read-only lookup of the current default route. When several match, the one
# with the lowest effective metric wins and match_count tells how many there
# were. Typical use: feed next_hop into a precondition guarding a
# default-gateway change.
data "windows_net_route" "current_default" {
  destination_prefix = "0.0.0.0/0"
}

output "default_gateway" {
  value       = data.windows_net_route.current_default.next_hop
  description = "Gateway address of the winning default route."
}

output "default_match_count" {
  value       = data.windows_net_route.current_default.match_count
  description = "How many default routes matched before the lowest-effective-metric winner was picked."
}
