# Registry: one value per REG_* type, plus env vars (machine + user scope).
resource "windows_registry_value" "version" {
  hive         = "HKLM"
  path         = "SOFTWARE\\CliTest-${var.test_suffix}"
  name         = "Version"
  type         = "REG_SZ"
  value_string = "1.0.0-${var.test_suffix}"
}

resource "windows_registry_value" "install_dir" {
  hive         = "HKLM"
  path         = "SOFTWARE\\CliTest-${var.test_suffix}"
  name         = "InstallDir"
  type         = "REG_EXPAND_SZ"
  value_string = "%ProgramData%\\cli-test-${var.test_suffix}"
}

resource "windows_registry_value" "search_paths" {
  hive          = "HKLM"
  path          = "SOFTWARE\\CliTest-${var.test_suffix}"
  name          = "SearchPaths"
  type          = "REG_MULTI_SZ"
  value_strings = ["C:\\data", "D:\\share"]
}

resource "windows_registry_value" "max_retries" {
  hive         = "HKLM"
  path         = "SOFTWARE\\CliTest-${var.test_suffix}"
  name         = "MaxRetries"
  type         = "REG_DWORD"
  value_string = "5"
}

resource "windows_registry_value" "cache_size" {
  hive         = "HKLM"
  path         = "SOFTWARE\\CliTest-${var.test_suffix}"
  name         = "CacheSizeBytes"
  type         = "REG_QWORD"
  value_string = "10737418240"
}

resource "windows_registry_value" "blob" {
  hive         = "HKLM"
  path         = "SOFTWARE\\CliTest-${var.test_suffix}"
  name         = "BinaryConfig"
  type         = "REG_BINARY"
  value_binary = "deadbeef0102"
}

resource "windows_environment_variable" "app_home" {
  name  = "CLI_TEST_HOME_${upper(var.test_suffix)}"
  value = windows_file.app_config.path
  scope = "machine"
}

resource "windows_environment_variable" "user_token" {
  name  = "CLI_TEST_TOKEN_${upper(var.test_suffix)}"
  value = "token-${var.test_suffix}"
  scope = "user"
}
