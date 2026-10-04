# Directories + files + ACLs. Covers every windows_directory knob and the
# main windows_file content sources (inline content only — source/source_url
# need local artifacts or network and are covered by the Go suite).

resource "windows_directory" "app_root" {
  path = "C:\\ProgramData\\cli-test-${var.test_suffix}"
}

resource "windows_directory" "app_logs" {
  path       = "C:\\ProgramData\\cli-test-${var.test_suffix}\\logs"
  attributes = ["hidden"]
}

resource "windows_directory" "scratch" {
  path             = "C:\\ProgramData\\cli-test-${var.test_suffix}\\scratch"
  recursive_delete = true
}

resource "windows_file" "app_config" {
  path     = "C:\\ProgramData\\cli-test-${var.test_suffix}\\appsettings.json"
  content  = jsonencode({ Logging = { LogLevel = { Default = "Information" } }, Suffix = var.test_suffix })
  encoding = "utf8bom"

  create_parents = true
  attributes     = ["archive"]

  depends_on = [windows_directory.app_root]
}

resource "windows_file" "motd" {
  path    = "C:\\ProgramData\\cli-test-${var.test_suffix}\\motd.txt"
  content = "Managed by terraform-cli fixture (${var.test_suffix}). Do not edit by hand.\r\n"

  create_parents = true
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

  access_rule {
    identity = windows_local_user.svc.name
    rights   = ["Read"]
  }
}
