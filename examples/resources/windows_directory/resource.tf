# A plain directory, created with any missing parents.
resource "windows_directory" "app_logs" {
  path = "C:\\ProgramData\\app\\logs"
}

# A hidden directory; attributes are applied in place without recreation.
resource "windows_directory" "cache" {
  path       = "C:\\ProgramData\\app\\cache"
  attributes = ["hidden"]
}

# A directory whose content Terraform is allowed to discard on destroy.
# Without recursive_delete, destroying a non-empty directory fails explicitly
# instead of silently discarding files not managed by Terraform.
resource "windows_directory" "scratch" {
  path             = "C:\\ProgramData\\app\\scratch"
  recursive_delete = true

  # Bound every remote operation explicitly. Without this block each operation
  # defaults to 10 minutes; a stalled PowerShell/SSH session then surfaces a
  # timeout diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "20m"
    read   = "5m"
    update = "20m"
    delete = "20m"
  }
}

# A directory under a path whose parents must already exist.
resource "windows_directory" "strict_parent" {
  path                      = "C:\\ProgramData\\app\\strict"
  create_parent_directories = false
}

# Declaring a directory absent removes it (recursively, per recursive_delete)
# if it exists, and is a no-op otherwise.
resource "windows_directory" "decommissioned" {
  path   = "C:\\ProgramData\\old_app"
  ensure = "absent"
}
