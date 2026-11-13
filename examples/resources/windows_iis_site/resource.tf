# Manage an IIS site with zero bindings: only the configured attributes are
# written; everything else on the host is left untouched. The site stays
# Stopped (with a warning) while it has no bindings — IIS cannot run an
# unbound site — and starts once windows_iis_binding adds one.
#
# Requires IIS on the target host (WebAdministration module): install it
# with windows_feature first (Web-Server; add Web-Mgmt-Console /
# Web-Scripting-Tools for the module on Server Core).
resource "windows_feature" "iis" {
  name                     = "Web-Server"
  include_management_tools = true
}

resource "windows_directory" "web" {
  path = "C:\\inetpub\\tf-acc-site"
}

resource "windows_iis_app_pool" "web" {
  name = "web"

  depends_on = [windows_feature.iis]
}

resource "windows_iis_site" "web" {
  name             = "web"
  physical_path    = windows_directory.web.path
  application_pool = windows_iis_app_pool.web.name

  auto_start        = true
  preload_enabled   = false
  enabled_protocols = "http"

  log_enabled   = true
  log_format    = "W3C"
  log_directory = "%SystemDrive%\\inetpub\\logs\\LogFiles"

  connection_timeout_seconds = 120
  max_connections            = 0 # unlimited

  state = "Started"

  depends_on = [windows_feature.iis]

  # Bound every remote operation explicitly. Without this block each operation
  # defaults to 10 minutes; a stalled PowerShell/SSH session then surfaces a
  # timeout diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "10m"
    read   = "10m"
    update = "10m"
    delete = "10m"
  }
}
