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

# Minimal example: rename the target Windows host to "WEB01".
# Rename-Computer queues the new name; it becomes active on the next reboot.
# This resource never reboots on its own — surface `reboot_pending` to a
# downstream null_resource / windows_reboot module to orchestrate the reboot.
resource "windows_hostname" "this" {
  name  = "WEB01"
  force = true

  # Bound every remote operation explicitly: without this block each
  # operation defaults to 10 minutes, and a stalled rename or read-back
  # surfaces a timeout diagnostic instead of blocking Terraform
  # indefinitely.
  timeouts = {
    create = "20m"
    read   = "5m"
    update = "20m"
    delete = "20m"
  }
}

output "hostname_reboot_pending" {
  value       = windows_hostname.this.reboot_pending
  description = "True when the target host must reboot to activate the rename."
}

output "hostname_current_name" {
  value       = windows_hostname.this.current_name
  description = "Active computer name (may still be the previous name until reboot)."
}
