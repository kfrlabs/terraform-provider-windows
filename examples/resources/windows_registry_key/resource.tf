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

# ---------------------------------------------------------------------------
# Ensure a key exists, without touching values (defaults: no purge, the key
# is left in place on destroy)
# ---------------------------------------------------------------------------
resource "windows_registry_key" "app" {
  hive = "HKLM"
  path = "SOFTWARE\\MyApp"

  # Bound every remote operation explicitly: without this block each
  # operation defaults to 10 minutes, and a stalled registry operation
  # surfaces a timeout diagnostic instead of blocking Terraform
  # indefinitely.
  timeouts = {
    create = "20m"
    read   = "5m"
    update = "20m"
    delete = "20m"
  }
}

# ---------------------------------------------------------------------------
# Opt-in purge: delete unmanaged value names, keep the managed ones
# ---------------------------------------------------------------------------
resource "windows_registry_value" "version" {
  hive         = "HKLM"
  path         = "SOFTWARE\\MyApp"
  name         = "Version"
  type         = "REG_SZ"
  value_string = "2.5.1"
}

resource "windows_registry_key" "managed" {
  hive = "HKLM"
  path = "SOFTWARE\\MyApp"

  # The purge set is the live enumeration MINUS managed_value_names. No
  # Terraform state outside this resource is consulted, so every name owned
  # by a windows_registry_value resource must be listed explicitly,
  # including "" for the Default value. Same hive/path/name must have a
  # single owner: managing one name from both resources is last-write-wins.
  purge_unknown_values = true
  managed_value_names  = ["Version"]

  depends_on = [windows_registry_value.version]
}

# ---------------------------------------------------------------------------
# Remove the whole key (including subkeys) on destroy
# ---------------------------------------------------------------------------
resource "windows_registry_key" "ephemeral" {
  hive = "HKCU"
  path = "SOFTWARE\\MyEphemeralApp"

  delete_key_on_destroy = true
  recursive             = true
}
