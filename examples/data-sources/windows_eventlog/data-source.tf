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

# Read the observed state of the Application log (read-only, no lifecycle).
data "windows_eventlog" "application" {
  name = "Application"
}

output "application_size_bytes" {
  value = data.windows_eventlog.application.maximum_size_bytes
}

output "application_retention" {
  value = data.windows_eventlog.application.retention
}

# Inspect a log managed by the windows_eventlog resource in the same
# configuration. The data source returns the observed live state, including
# the informational record_count / file_size_bytes counters and the
# Group Policy policy_override flag.
data "windows_eventlog" "managed" {
  name = windows_eventlog.application.name
}
