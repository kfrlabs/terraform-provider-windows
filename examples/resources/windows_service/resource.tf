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

# Minimal example: a service running as LocalSystem.
resource "windows_service" "example" {
  name         = "example-svc"
  display_name = "Example Service"
  description  = "Managed by Terraform."
  binary_path  = "C:\\Program Files\\Example\\example.exe --run"
  start_type   = "Automatic"
  status       = "Running"
}

# Slow or heavily loaded host: bound every remote operation explicitly.
# Without this block each operation defaults to 10 minutes; a stalled
# PowerShell/SSH session then surfaces a timeout diagnostic instead of
# blocking Terraform indefinitely.
resource "windows_service" "slow_host" {
  name         = "slow-svc"
  display_name = "Slow Host Service"
  binary_path  = "C:\\Program Files\\Example\\example.exe --run"
  start_type   = "Automatic"
  status       = "Running"

  timeouts = {
    create = "20m"
    read   = "5m"
    update = "20m"
    delete = "20m"
  }
}

# Write-only credential rotation (issue #194): the plaintext never reaches
# `terraform.tfstate`. Rotation is driven exclusively by
# `service_password_wo_version` — change it and re-apply with the new password
# value; changing only `service_password_wo` without changing the version is
# a no-op.
resource "windows_service" "app_wo" {
  name                        = "myapp-wo"
  display_name                = "My Application (WriteOnly)"
  description                 = "Business application managed by Terraform."
  binary_path                 = "C:\\Program Files\\MyApp\\myapp.exe"
  start_type                  = "Automatic"
  status                      = "Running"
  service_account             = "DOMAIN\\svc-myapp"
  service_password_wo         = var.svc_myapp_password
  service_password_wo_version = 1
  dependencies                = ["LanmanServer", "Tcpip"]
}

# Advanced example: service running under a domain account with dependencies.
resource "windows_service" "app" {
  name             = "myapp"
  display_name     = "My Application"
  description      = "Business application managed by Terraform."
  binary_path      = "C:\\Program Files\\MyApp\\myapp.exe"
  start_type       = "AutomaticDelayedStart"
  status           = "Running"
  service_account  = "DOMAIN\\svc-myapp"
  service_password = var.svc_myapp_password
  dependencies     = ["LanmanServer", "Tcpip"]
}
