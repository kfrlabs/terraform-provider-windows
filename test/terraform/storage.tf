# A file secured right after being written is the realistic pattern for
# windows_file + windows_file_acl cohabiting the same path (windows_file
# preserves the security descriptor on content updates, per its docs).

resource "windows_file" "app_config" {
  path     = "C:\\ProgramData\\pushed-test-${var.test_suffix}\\appsettings.json"
  content  = jsonencode({ Logging = { LogLevel = { Default = "Information" } }, Suffix = var.test_suffix })
  encoding = "utf8bom"

  create_parents = true
  attributes     = ["archive"]
}

resource "windows_file_acl" "app_config" {
  path  = windows_file.app_config.path
  owner = "BUILTIN\\Administrators"

  inheritance_enabled = false

  access_rule {
    identity = "NT AUTHORITY\\SYSTEM"
    rights   = ["FullControl"]
  }

  access_rule {
    identity = "BUILTIN\\Administrators"
    rights   = ["FullControl"]
  }

  # Cross-resource dependency: the service account from identity.tf gets
  # read access to the file it does not own.
  access_rule {
    identity = windows_local_user.svc_app.name
    rights   = ["Read"]
  }
}

resource "windows_registry_value" "app_version" {
  hive         = "HKLM"
  path         = "SOFTWARE\\PushedTest-${var.test_suffix}"
  name         = "Version"
  type         = "REG_SZ"
  value_string = "1.0.0-${var.test_suffix}"
}

resource "windows_registry_value" "app_install_dir" {
  hive         = "HKLM"
  path         = "SOFTWARE\\PushedTest-${var.test_suffix}"
  name         = "InstallDir"
  type         = "REG_EXPAND_SZ"
  value_string = "%ProgramData%\\pushed-test-${var.test_suffix}"
}

resource "windows_environment_variable" "app_home" {
  name  = "PUSHED_TEST_HOME_${upper(var.test_suffix)}"
  value = windows_file.app_config.path
  scope = "machine"
}
