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

# Read-only lookup of an existing certificate by thumbprint.
data "windows_certificate" "web" {
  thumbprint = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
}

# Lookup by subject, narrowed to the Personal store. When several certificates
# share the subject, the most recently issued one wins (most_recent defaults
# to true).
data "windows_certificate" "by_subject" {
  subject     = "CN=example.com"
  store_name  = "My"
  most_recent = true
}

output "web_not_after" {
  value       = data.windows_certificate.web.not_after
  description = "Expiry of the observed certificate (RFC 3339 UTC)."
}
