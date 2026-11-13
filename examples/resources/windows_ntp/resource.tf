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

# Minimal example: point the target host's W32Time service at public NTP
# peers. The time source is a singleton — this resource tunes it in place
# and never provisions anything new. Destroy is a no-op unless
# restore_on_destroy re-applies the pre-existing values captured at
# creation time.
resource "windows_ntp" "this" {
  type = "NTP"

  servers = [
    { address = "0.fr.pool.ntp.org" },
    { address = "1.fr.pool.ntp.org", flags = "0x1" },
  ]

  special_poll_interval_seconds = 900
  reliable                      = false
  ntp_server_enabled            = false
  restore_on_destroy            = true

  # Bound every remote operation explicitly: without this block each
  # operation defaults to 5 minutes, and a stalled registry write,
  # w32tm call or read-back surfaces a timeout diagnostic instead of
  # blocking Terraform indefinitely.
  timeouts = {
    create = "5m"
    read   = "5m"
    update = "5m"
    delete = "5m"
  }
}

output "type" {
  value       = windows_ntp.this.type
  description = "W32Time sync type."
}

output "current_source" {
  value       = windows_ntp.this.current_source
  description = "Current time source as reported by w32tm /query /source."
}
