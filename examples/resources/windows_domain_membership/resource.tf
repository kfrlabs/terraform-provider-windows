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

variable "windows_host" {
  type = string
}

variable "windows_username" {
  type = string
}

variable "windows_password" {
  type      = string
  sensitive = true
}

variable "domain_join_password" {
  type        = string
  sensitive   = true
  description = "Domain account password for the join. Kept in state (Sensitive); use password_wo instead when destroy must stay a no-op."
}

# Minimal example: join the target host to corp.example.com.
# Add-Computer only queues the join; it takes full effect on the next reboot.
# With restart = false (default) the host must be rebooted out-of-band —
# surface pending_reboot to a downstream null_resource / windows_reboot
# module to orchestrate the reboot.
resource "windows_domain_membership" "this" {
  domain = "corp.example.com"

  join_credential = {
    username = "joiner@corp.example.com"
    password = var.domain_join_password
  }

  # Bound every remote operation explicitly: without this block create and
  # delete default to 15 minutes (a stalled domain-controller call surfaces
  # a timeout diagnostic instead of blocking Terraform indefinitely).
  timeouts = {
    create = "15m"
    read   = "5m"
    update = "5m"
    delete = "15m"
  }
}

# Advanced example: place the computer account in a dedicated OU and
# schedule a detached host reboot ~60s after the join when a reboot is
# required (restart = true only takes effect when a pending reboot is
# reported). The OU is create-only: changing ou_path later only warns and
# never moves the account.
resource "windows_domain_membership" "ou" {
  domain  = "corp.example.com"
  ou_path = "OU=Servers,DC=corp,DC=example,DC=com"

  join_credential = {
    username = "joiner@corp.example.com"
    password = var.domain_join_password
  }

  restart = true
}

# Unjoin-on-destroy example: leaving the domain on destroy requires the
# state-persisted password (password_wo is WriteOnly and unavailable at
# destroy time, so that combination is rejected at plan time).
resource "windows_domain_membership" "ephemeral" {
  domain = "corp.example.com"

  join_credential = {
    username = "joiner@corp.example.com"
    password = var.domain_join_password
  }

  unjoin_on_destroy     = true
  unjoin_workgroup_name = "WORKGROUP"
}

output "domain_computer_name" {
  value       = windows_domain_membership.this.computer_name
  description = "Active computer name of the domain-joined host."
}

output "domain_pending_reboot" {
  value       = windows_domain_membership.this.pending_reboot
  description = "True when the target host must reboot to complete the join."
}
