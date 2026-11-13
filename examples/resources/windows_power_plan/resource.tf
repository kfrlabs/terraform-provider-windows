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

# Minimal example: switch the target host to the High performance plan and
# never spin the disk down on AC power. The active plan is a singleton —
# this resource activates it in place and never provisions anything new.
# Destroy is a no-op unless restore_on_destroy re-applies the pre-existing
# plan and values captured at creation time.
resource "windows_power_plan" "this" {
  plan = "high_performance"

  settings = [
    { subgroup = "SUB_DISK", setting = "DISKIDLE", ac_value = 0 },
    { subgroup = "SUB_SLEEP", setting = "STANDBYIDLE", ac_value = 0, dc_value = 0 },
  ]

  restore_on_destroy = true

  # Bound every remote operation explicitly: without this block each
  # operation defaults to 5 minutes, and a stalled powercfg or read-back
  # surfaces a timeout diagnostic instead of blocking Terraform
  # indefinitely.
  timeouts = {
    create = "5m"
    read   = "5m"
    update = "5m"
    delete = "5m"
  }
}

output "plan_guid" {
  value       = windows_power_plan.this.plan_guid
  description = "Resolved GUID of the active power plan."
}

output "plan_name" {
  value       = windows_power_plan.this.plan_name
  description = "Localised display name of the active power plan."
}
