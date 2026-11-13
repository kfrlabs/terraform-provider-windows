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

# Minimal example: format the carved data partition to NTFS with a label.
# Formatting destroys the partition's data: a partition that already carries
# a file system is refused with `already_formatted` unless
# `allow_format_existing` is set, and protected partitions fail closed with
# `protected_storage`.
resource "windows_volume" "data" {
  partition_id      = windows_partition.data.id
  file_system       = "NTFS"
  file_system_label = "TFDATA"
}

# Advanced example: exFAT with an explicit allocation unit size and a slow
# full format (which scans for bad sectors). Deleting the resource only drops
# the adoption from state: the volume and its data are left untouched.
# Consider `lifecycle { prevent_destroy = true }` for volumes holding data.
resource "windows_volume" "backup" {
  partition_id         = windows_partition.data.id
  file_system          = "exFAT"
  file_system_label    = "BACKUP"
  allocation_unit_size = 131072 # 128 KiB

  full_format = true

  lifecycle {
    prevent_destroy = true
  }
}
