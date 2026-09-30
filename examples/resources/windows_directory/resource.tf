terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.0"
    }
  }
}

provider "windows" {
  host             = var.windows_host
  username         = var.windows_username
  private_key_path = var.windows_private_key_path
}

resource "windows_directory" "application" {
  path           = "C:\\ProgramData\\Example\\Application"
  create_parents  = true
  attributes      = ["archive"]
  recursive_delete = true
}

variable "windows_host" { type = string }
variable "windows_username" { type = string }
variable "windows_private_key_path" { type = string }
