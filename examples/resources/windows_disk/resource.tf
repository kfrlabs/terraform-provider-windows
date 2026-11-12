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

# Minimal example: adopt a data disk by its stable UniqueId and keep it
# online and writable. The resource never creates or destroys disk hardware:
# applying adopts the matching disk (its UniqueId becomes the Terraform ID)
# and destroying only drops the adoption from state.
resource "windows_disk" "data" {
  unique_id = "SCSI\\DISK&VEN_MSFT&PROD_VIRTUAL_DISK&REV_1.0"
}

# Advanced example: adopt an uninitialized (RAW) disk by serial number,
# initialize it to GPT and take it offline (e.g. a disk reserved for a
# cluster or a backup rotation). Only a RAW disk is initialized in place:
# adopting an already-initialized disk with a different style is a
# partition_style_mismatch error.
resource "windows_disk" "reserved" {
  serial_number   = "6000c296-abc123"
  partition_style = "GPT"
  is_offline      = true
}
