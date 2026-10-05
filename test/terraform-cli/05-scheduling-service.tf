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
      # Trigger durations are string-typed CIM properties assigned and read
      # back verbatim, so the full XSD grammar is valid here — including forms
      # settings.execution_time_limit must reject (P1M4DT2H5M).
      execution_time_limit = "PT5M"
      delay                = "PT1M"
    }
  ]

  # settings.execution_time_limit is converted through XmlConvert::ToTimeSpan
  # on apply because New-ScheduledTaskSettingsSet -ExecutionTimeLimit is a
  # [TimeSpan]. Any XSD duration of days or less works (P3D is exactly 72h);
  # year/month components are rejected, since ToTimeSpan would approximate them.
  settings = {
    execution_time_limit = "PT4H"
  }
}

resource "windows_service" "fixture" {
  name         = "CliTest-${var.test_suffix}"
  display_name = "CLI-Test Fixture Service (${var.test_suffix})"
  description  = "Created by test/terraform-cli - safe to delete."
  binary_path  = "C:\\Windows\\System32\\cmd.exe"
  start_type   = "Manual"
  status       = "Stopped"
}
