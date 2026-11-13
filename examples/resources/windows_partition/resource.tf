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

# Minimal example: carve a data partition from the largest free extent of an
# adopted disk and give it a drive letter. The partition is always created
# with -AssignDriveLetter:$false first, then the configured letter is assigned
# explicitly (no random letters, no Explorer "format disk" race).
resource "windows_partition" "data" {
  disk_unique_id   = windows_disk.data.id
  use_maximum_size = true
  drive_letter     = "E"
  gpt_type         = "basic_data"
}

# Advanced example: carve an explicitly sized partition at the first fitting
# extent, without a drive letter. Growing later is in-place (set a larger
# size_bytes); shrinking is refused with shrink_not_supported in v1.
# Deleting the resource destroys the partition and its data: consider
# `lifecycle { prevent_destroy = true }` for partitions holding data.
resource "windows_partition" "sized" {
  disk_unique_id = windows_disk.data.id
  size_bytes     = 10737418240 # 10 GiB

  lifecycle {
    prevent_destroy = true
  }
}
