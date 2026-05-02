terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
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

# Minimal example: install the latest available version of Visual Studio Code.
resource "windows_winget_package" "vscode" {
  package_id = "Microsoft.VisualStudioCode"
  source     = "winget"
}

# Pinned version: install a specific version of Node.js LTS.
resource "windows_winget_package" "nodejs" {
  package_id = "OpenJS.NodeJS.LTS"
  source     = "winget"
  version    = "20.11.0"
}

# Custom installer arguments via -Override (MSI silent install with custom dir).
resource "windows_winget_package" "myapp" {
  package_id = "Contoso.MyApp"
  source     = "winget"
  override   = "/S /ALLUSERS"
}

# Microsoft Store source (msstore). Note: may require interactive auth on some hosts.
resource "windows_winget_package" "windows_terminal" {
  package_id = "9N0DX20HK701"
  source     = "msstore"
}
