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

# Tune the Application log in place: grow the maximum size and archive the
# log instead of overwriting when it fills. Only the configured attributes
# are assigned before SaveChanges(); everything else on the host is left
# untouched. The log always exists, so this resource never provisions
# anything new — and destroy makes no remote change unless
# restore_on_destroy re-applies the pre-existing values captured at
# creation time.
resource "windows_eventlog" "application" {
  name               = "Application"
  maximum_size_bytes = 1073741824 # 1 GiB (multiple of 64 KiB, at least 1 MiB)
  retention          = "archive"  # overwrite | archive | retain

  restore_on_destroy = true

  # Bound every remote operation explicitly: without this block each
  # operation defaults to 5 minutes, and a stalled PowerShell/SSH session
  # then surfaces a timeout diagnostic instead of blocking Terraform
  # indefinitely.
  timeouts = {
    create = "5m"
    read   = "5m"
    update = "5m"
    delete = "5m"
  }
}

# A modern channel name contains "/": it is matched literally, never as a
# path. Enabling a disabled Analytic or Debug channel clears it.
resource "windows_eventlog" "powershell" {
  name               = "Microsoft-Windows-PowerShell/Operational"
  enabled            = true
  maximum_size_bytes = 268435456 # 256 MiB
}

output "application_size_bytes" {
  value       = windows_eventlog.application.maximum_size_bytes
  description = "Maximum size of the Application log file, in bytes."
}

output "powershell_enabled" {
  value       = windows_eventlog.powershell.enabled
  description = "Whether the PowerShell Operational channel is enabled."
}
