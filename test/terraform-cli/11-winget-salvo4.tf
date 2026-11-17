# winget_package aggressive campaign (salvo4, 2026-11-17, LAB 203).
# Gated: needs internet on the target (winget source reachable).
# Light, quiet, cleanly uninstallable packages only — parameters vary from
# the 06-packages VSCode fixture on purpose (pinned version, timeouts
# attribute syntax, override forwarding, data source read-back).

resource "windows_winget_package" "salvo4_pinned" {
  count = var.enable_network_tests ? 1 : 0

  package_id = "BurntSushi.ripgrep.MSVC"
  source     = "winget"
  version    = "15.2.0"

  # NOTE: attribute syntax with equals sign (a `timeouts {}` block is rejected
  # by terraform validate).
  timeouts = {
    create = "20m"
    read   = "5m"
    update = "20m"
    delete = "20m"
  }
}

resource "windows_winget_package" "salvo4_override" {
  count = var.enable_network_tests ? 1 : 0

  package_id = "PuTTY.PuTTY"
  source     = "winget"
  override   = "REBOOT=ReallySuppress"
}

data "windows_winget_package" "salvo4_pinned" {
  count = var.enable_network_tests ? 1 : 0

  package_id = "BurntSushi.ripgrep.MSVC"
  source     = "winget"

  depends_on = [windows_winget_package.salvo4_pinned]
}
