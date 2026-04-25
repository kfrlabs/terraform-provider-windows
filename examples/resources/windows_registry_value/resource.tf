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

# ---------------------------------------------------------------------------
# REG_SZ — plain string value
# ---------------------------------------------------------------------------
resource "windows_registry_value" "reg_sz" {
  hive         = "HKLM"
  path         = "SOFTWARE\\MyApp"
  name         = "Version"
  type         = "REG_SZ"
  value_string = "2.5.1"
}

# ---------------------------------------------------------------------------
# REG_EXPAND_SZ — string with %VARIABLE% tokens (not expanded on read by default)
# ---------------------------------------------------------------------------
resource "windows_registry_value" "reg_expand_sz" {
  hive         = "HKLM"
  path         = "SOFTWARE\\MyApp"
  name         = "InstallDir"
  type         = "REG_EXPAND_SZ"
  value_string = "%ProgramFiles%\\MyApp"

  # expand_environment_variables = false  (default)
  # Set to true to read the expanded path; note this may cause perpetual
  # plan diffs if the expansion changes between reads (e.g. drive letter
  # change after OS reinstall).
}

# ---------------------------------------------------------------------------
# REG_MULTI_SZ — multi-string list (use [] for an empty list)
# ---------------------------------------------------------------------------
resource "windows_registry_value" "reg_multi_sz" {
  hive          = "HKLM"
  path          = "SOFTWARE\\MyApp"
  name          = "SearchPaths"
  type          = "REG_MULTI_SZ"
  value_strings = ["C:\\data", "D:\\share", "\\\\server\\archive"]
}

# ---------------------------------------------------------------------------
# REG_DWORD — 32-bit unsigned integer expressed as a decimal string
# Valid range: 0 .. 4294967295
# ---------------------------------------------------------------------------
resource "windows_registry_value" "reg_dword" {
  hive         = "HKLM"
  path         = "SOFTWARE\\MyApp"
  name         = "MaxRetries"
  type         = "REG_DWORD"
  value_string = "5"
}

# ---------------------------------------------------------------------------
# REG_QWORD — 64-bit unsigned integer expressed as a decimal string
# Valid range: 0 .. 18446744073709551615
# ---------------------------------------------------------------------------
resource "windows_registry_value" "reg_qword" {
  hive         = "HKLM"
  path         = "SOFTWARE\\MyApp"
  name         = "CacheSizeBytes"
  type         = "REG_QWORD"
  value_string = "10737418240" # 10 GiB
}

# ---------------------------------------------------------------------------
# REG_BINARY — raw bytes as a lowercase hex string (no separators)
# An empty string "" represents a zero-length byte array.
# ---------------------------------------------------------------------------
resource "windows_registry_value" "reg_binary" {
  hive         = "HKLM"
  path         = "SOFTWARE\\MyApp"
  name         = "BinaryConfig"
  type         = "REG_BINARY"
  value_binary = "deadbeef0102"
}

# ---------------------------------------------------------------------------
# REG_NONE — typeless data (zero-length or raw bytes)
# ---------------------------------------------------------------------------
resource "windows_registry_value" "reg_none" {
  hive         = "HKLM"
  path         = "SOFTWARE\\MyApp"
  name         = "Marker"
  type         = "REG_NONE"
  value_binary = "" # zero-length byte array
}

# ---------------------------------------------------------------------------
# Default value — name="" (the unnamed (Default) value shown in regedit)
# The resource ID ends with a trailing backslash: HKLM\SOFTWARE\MyApp\
# ---------------------------------------------------------------------------
resource "windows_registry_value" "default_value" {
  hive = "HKCU"
  path = "SOFTWARE\\MyApp"
  # name is omitted => defaults to "" (the Default value)
  type         = "REG_SZ"
  value_string = "DefaultContent"
}
