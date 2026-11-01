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

# Look up the observed state of an existing SMB share.
data "windows_smb_share" "finance" {
  name = "Finance"
}

output "finance_path" {
  value = data.windows_smb_share.finance.path
}

output "finance_read_access" {
  value = data.windows_smb_share.finance.read_access
}

output "finance_special" {
  value = data.windows_smb_share.finance.special
}
