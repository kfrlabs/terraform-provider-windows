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

# Read a specific registry value.
data "windows_registry_value" "product_name" {
  hive = "HKLM"
  path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
  name = "ProductName"
}

# Read a REG_EXPAND_SZ value with environment variable expansion.
data "windows_registry_value" "windir" {
  hive                         = "HKLM"
  path                         = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
  name                         = "windir"
  expand_environment_variables = true
}

output "windows_product_name" {
  value = data.windows_registry_value.product_name.value_string
}

output "windir_expanded" {
  value = data.windows_registry_value.windir.value_string
}
