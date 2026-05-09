terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.0"
    }
  }
}

provider "windows" {
  host      = var.windows_host
  username  = var.windows_username
  password  = var.windows_password
  auth_type = "ntlm"
}

# MSI from a local path on the target host. ProductCode is auto-extracted.
resource "windows_legacy_package" "sevenzip" {
  name           = "7zip"
  installer_type = "msi"
  source_path    = "C:\\Packages\\7z2407-x64.msi"
  checksum       = "sha256:b099a25b8b4c9e0d6f2e4f3c2c0a3b6d5d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80"
}

# MSI fetched from an internal HTTPS artifact server, with reboot tolerated.
resource "windows_legacy_package" "npp" {
  name             = "notepadpp"
  installer_type   = "msi"
  source_url       = "https://artifacts.internal.example/npp/8.6.4.msi"
  checksum         = "sha256:1a2b3c4d5e6f7081928374655463728190a1b2c3d4e5f60718293a4b5c6d7e8f"
  valid_exit_codes = [0, 3010]
  timeout_seconds  = 1800
}

# EXE installer (NSIS) located by DisplayName for uninstall.
resource "windows_legacy_package" "vlc" {
  name                 = "vlc"
  installer_type       = "exe"
  source_url           = "https://artifacts.internal.example/vlc/vlc-3.0.20-win64.exe"
  checksum             = "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
  install_args         = ["/S"]
  uninstall_args       = ["/S"]
  display_name_pattern = "VLC media player*"
}

# EXE with explicit uninstall command, custom env (sensitive) and longer timeout.
resource "windows_legacy_package" "vendor_tool" {
  name              = "vendor-tool"
  installer_type    = "exe"
  source_path       = "C:\\Packages\\vendor-tool-2.4.0.exe"
  install_args      = ["/quiet", "/norestart"]
  uninstall_command = "C:\\Program Files\\Vendor\\Tool\\uninstall.exe"
  uninstall_args    = ["/silent"]
  valid_exit_codes  = [0, 1641, 3010]
  timeout_seconds   = 3600

  environment = {
    LICENSE_KEY = var.vendor_license_key
    HTTP_PROXY  = "http://proxy.internal:3128"
  }
}

variable "windows_host" { type = string }
variable "windows_username" { type = string }
variable "windows_password" {
  type      = string
  sensitive = true
}
variable "vendor_license_key" {
  type      = string
  sensitive = true
  default   = ""
}
