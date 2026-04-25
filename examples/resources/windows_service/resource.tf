terraform {
  required_providers {
    windows = {
      source  = "ecritel/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host      = var.windows_host
  username  = var.windows_username
  password  = var.windows_password
  auth_type = "ntlm"
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
