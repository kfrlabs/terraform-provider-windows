# Packages + feature + hostname. All gated: they need internet, a DISM
# payload, or a machine rename — never on by default on a shared lab host.

resource "windows_legacy_package" "sevenzip" {
  count = var.enable_network_tests ? 1 : 0

  name             = "7zip-${var.test_suffix}"
  installer_type   = "msi"
  source_url       = "https://www.7-zip.org/a/7z2408-x64.msi"
  valid_exit_codes = [0, 3010]
  timeout_seconds  = 900
}

resource "windows_winget_package" "vscode" {
  count = var.enable_network_tests ? 1 : 0

  package_id = "Microsoft.VisualStudioCode"
  source     = "winget"
}

resource "windows_feature" "web_server" {
  count = var.enable_feature_test ? 1 : 0

  name = "Web-Server"
}

resource "windows_hostname" "fixture" {
  count = var.enable_hostname_test ? 1 : 0

  name  = var.expected_hostname
  force = true
}
