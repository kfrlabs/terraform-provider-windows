# Gated behind enable_network_tests: both need outbound internet from the
# container, and windows_winget_package additionally needs the App Installer
# package, which a bare servercore:ltsc2025 image does not ship. See
# test/terraform/README.md, "Known container limitations", before filing an
# issue about either failing with count = 0.

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
