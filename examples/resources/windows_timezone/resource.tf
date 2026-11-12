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

# Minimal example: set the target host's system time zone to UTC.
# The zone is a singleton — this resource sets it in place and never
# provisions anything new. Destroy is a no-op unless restore_on_destroy
# re-applies the pre-existing zone captured at creation time.
resource "windows_timezone" "this" {
  timezone_id        = "UTC"
  restore_on_destroy = true

  # Bound every remote operation explicitly: without this block each
  # operation defaults to 5 minutes, and a stalled Set-TimeZone or read-back
  # surfaces a timeout diagnostic instead of blocking Terraform
  # indefinitely.
  timeouts = {
    create = "5m"
    read   = "5m"
    update = "5m"
    delete = "5m"
  }
}

output "timezone_id" {
  value       = windows_timezone.this.timezone_id
  description = "Configured Windows time zone ID."
}

output "current_utc_offset" {
  value       = windows_timezone.this.current_utc_offset
  description = "Live effective UTC offset (base plus the active DST delta, if any)."
}
