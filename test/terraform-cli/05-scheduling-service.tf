# Scheduled task (driven by the fixture service account) + dedicated service.
# NOTE: principal/actions/triggers/settings are TPF attributes (object syntax
# with `= { }` / `= [ { } ]`), not nested blocks.

# NOTE: no `principal` block on purpose (issue #101, see README): a
# Password principal fails Register on PowerShell 5.1 one-shot targets
# (this container has no pwsh, so the provider falls back to one
# powershell.exe per call and the stdin-delivered password does not reach
# Register). The task runs as SYSTEM by default, which still exercises the
# full resource + data source lifecycle. Re-add a Password principal when
# validating against a host with PowerShell 7 (persistent session).
resource "windows_scheduled_task" "fixture" {
  name        = "CliTest-${var.test_suffix}"
  path        = "\\CliTest\\"
  description = "terraform-cli fixture task - managed by Terraform."
  enabled     = true

  actions = [
    {
      execute   = "powershell.exe"
      arguments = "-NoProfile -Command \"Write-Output 'cli-test-${var.test_suffix}'\""
    }
  ]

  triggers = [
    {
      type           = "Daily"
      start_boundary = "2026-01-01T02:00:00Z"
      days_interval  = 1
    }
  ]

  # NOTE: no `settings` block on purpose (issue #100, see README): the
  # provider defaults settings.execution_time_limit to "PT72H" and passes the
  # raw ISO 8601 string to New-ScheduledTaskSettingsSet -ExecutionTimeLimit,
  # which requires a TimeSpan ("Cannot convert value PT72H"). Any settings
  # block fails Create until the provider converts ISO 8601 to TimeSpan.
}

resource "windows_service" "fixture" {
  name         = "CliTest-${var.test_suffix}"
  display_name = "CLI-Test Fixture Service (${var.test_suffix})"
  description  = "Created by test/terraform-cli - safe to delete."
  binary_path  = "C:\\Windows\\System32\\cmd.exe"
  start_type   = "Manual"
  status       = "Stopped"
}
