terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host     = "win01.example.local"
  username = "Administrator"
  password = var.windows_password
}

# Inline text content.
resource "windows_file" "motd" {
  path    = "C:\\ProgramData\\motd.txt"
  content = "Managed by Terraform. Do not edit by hand.\r\n"
}

# Rendered template, UTF-8 with BOM, parent directories created on demand.
resource "windows_file" "app_config" {
  path     = "C:\\inetpub\\wwwroot\\app\\appsettings.json"
  content  = jsonencode({ Logging = { LogLevel = { Default = "Information" } } })
  encoding = "utf8bom"

  create_parents = true
  attributes     = ["archive"]
}

# Secret content kept out of the Terraform state entirely (write-only).
# Bump content_wo_version to force a rewrite: Terraform cannot diff a
# write-only value.
resource "windows_file" "connection_string" {
  path               = "C:\\inetpub\\wwwroot\\app\\secrets.config"
  content_wo         = var.connection_string
  content_wo_version = "1"
  attributes         = ["hidden"]
}

# Upload a local file; editing it locally produces a diff on the next plan.
resource "windows_file" "bootstrap_script" {
  path   = "C:\\ProgramData\\bootstrap.ps1"
  source = "${path.module}/files/bootstrap.ps1"
}

# Deploy an artifact from an internal repository. The provider downloads it and
# streams it over SSH, so the Windows host needs no outbound access.
resource "windows_file" "agent_installer" {
  path              = "C:\\Temp\\agent.msi"
  source_url        = "https://repo.example.local/agent/1.4.2/agent.msi"
  source_url_sha256 = "9f2b1c1f0a7e4d3b8c6a5e4f3d2c1b0a9f8e7d6c5b4a39281706f5e4d3c2b1a0"

  source_url_headers = {
    Authorization = "Bearer ${var.repo_token}"
  }
}

# Large artifact: let the host download it directly. A pinned checksum is then
# mandatory, since the provider never sees the payload.
resource "windows_file" "big_artifact" {
  path              = "C:\\Temp\\runtime.zip"
  source_url        = "https://repo.example.local/runtime/9.0/runtime.zip"
  source_url_sha256 = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
  download_on       = "target"

  timeouts {
    create = "30m"
  }
}

# Refuse to clobber a file that already exists.
resource "windows_file" "never_clobber" {
  path      = "C:\\ProgramData\\app\\license.dat"
  content   = var.license
  overwrite = false
}

variable "windows_password" { sensitive = true }
variable "connection_string" { sensitive = true }
variable "repo_token" { sensitive = true }
variable "license" { sensitive = true }
