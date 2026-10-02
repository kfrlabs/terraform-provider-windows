# Driven by the service account created in identity.tf: the realistic case
# a single-resource test cannot cover (principal + password rotation +
# dependent local user all converging in the same plan).
#
# Needs the Task Scheduler ("Schedule") service running on the target —
# it does run by default in the tfacc-win container, but verify with
# `Get-Service Schedule` before treating a failure here as a provider bug
# (see test/terraform/README.md, "Known container limitations").
#
# NOTE: principal/actions/triggers/settings are TPF *attributes*
# (SingleNestedAttribute / ListNestedAttribute), so they use `= { ... }`
# object syntax, not `name { ... }` block syntax. The shipped example under
# examples/resources/windows_scheduled_task/resource.tf currently uses block
# syntax and does not parse — tracked separately.
resource "windows_scheduled_task" "pushed_test" {
  name        = "PushedTest-${var.test_suffix}"
  path        = "\\PushedTest\\"
  description = "Pushed-test fixture task — managed by Terraform."
  enabled     = true

  principal = {
    user_id             = ".\\${windows_local_user.svc_app.name}"
    logon_type          = "Password"
    password_wo         = "Xk7!mQ2#nR9w"
    password_wo_version = 1
    run_level           = "Limited"
  }

  actions = [
    {
      execute   = "powershell.exe"
      arguments = "-NoProfile -Command \"Write-Output 'pushed-test-${var.test_suffix}'\""
    }
  ]

  triggers = [
    {
      type           = "Daily"
      start_boundary = "2026-01-01T02:00:00Z"
      days_interval  = 1
    }
  ]

  settings = {
    run_only_if_network_available = true
    multiple_instances            = "IgnoreNew"
  }
}
