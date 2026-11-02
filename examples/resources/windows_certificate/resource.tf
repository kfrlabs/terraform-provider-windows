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

# Import a public certificate from PEM. Only the first CERTIFICATE block is
# imported; the value is stored in state in normalised form.
resource "windows_certificate" "web" {
  certificate_pem = file("${path.module}/web.crt")
  friendly_name   = "tf-web"

  # Bound every remote operation explicitly. Without this block each operation
  # defaults to 10 minutes; a stalled PowerShell/SSH session then surfaces a
  # timeout diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "10m"
    read   = "5m"
    update = "10m"
    delete = "10m"
  }

  # Replacing a certificate removes the old thumbprint and adds the new one.
  # Create the replacement first so the store always holds a usable
  # certificate during rotation.
  lifecycle {
    create_before_destroy = true
  }
}

# Import a PFX bundle with an exportable private key. The bundle and password
# are WriteOnly: they never reach state or logs. Rotation is driven by
# pfx_wo_version: bump it and re-apply with the new bundle.
# Note: terraform import always records exportable = false in state. After
# importing a PFX-backed certificate, set exportable in configuration to match
# the host before the first apply (exportable forces replacement when it
# differs).
resource "windows_certificate" "web_pfx" {
  pfx_base64_wo   = filebase64("${path.module}/web.pfx")
  pfx_password_wo = var.pfx_password
  pfx_wo_version  = 1
  exportable      = true
  friendly_name   = "tf-web-pfx"

  lifecycle {
    create_before_destroy = true
  }
}

output "web_thumbprint" {
  value       = windows_certificate.web.thumbprint
  description = "SHA-1 thumbprint of the imported certificate."
}
