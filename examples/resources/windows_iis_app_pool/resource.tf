# Manage an IIS application pool: no managed code, always running, recycled
# nightly at 03:00. Only the configured attributes are written
# (Set-ItemProperty); everything else on the host is left untouched.
#
# Requires IIS on the target host (WebAdministration module): install it
# with windows_feature first (Web-Server; add Web-Mgmt-Console /
# Web-Scripting-Tools for the module on Server Core).
resource "windows_feature" "iis" {
  name                     = "Web-Server"
  include_management_tools = true
}

resource "windows_iis_app_pool" "api" {
  name                    = "api"
  managed_runtime_version = "" # No Managed Code
  managed_pipeline_mode   = "Integrated"
  start_mode              = "AlwaysRunning"

  idle_timeout_minutes               = 0 # disabled
  recycling_periodic_restart_minutes = 0 # disabled
  recycling_schedule                 = ["03:00:00"]
  recycling_private_memory_kb        = 1048576
  rapid_fail_protection              = true

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

# A pool running as a domain service account. The password is WriteOnly: it
# travels to the host on stdin, is never persisted in state, and is re-sent
# only when identity_password_wo_version changes (bump the version to rotate).
resource "windows_iis_app_pool" "svc" {
  name                         = "svc"
  identity_type                = "SpecificUser"
  identity_username            = "CONTOSO\\svc-web"
  identity_password_wo         = var.svc_web_password
  identity_password_wo_version = 1
  load_user_profile            = true

  depends_on = [windows_feature.iis]
}
