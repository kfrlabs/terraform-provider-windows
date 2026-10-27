# Identity: group + user + membership wired together (realistic pattern).
resource "windows_local_group" "fixture" {
  name        = "CliOperators-${var.test_suffix}"
  description = "terraform-cli fixture group - safe to delete."
}

resource "windows_local_user" "svc" {
  name                         = "svc-cli-${var.test_suffix}"
  full_name                    = "CLI Fixture Service Account"
  description                  = "Runs the terraform-cli fixture task."
  password_wo                  = var.svc_password
  password_wo_version          = 1
  enabled                      = true
  password_never_expires       = true
  user_may_not_change_password = true
  account_never_expires        = true

  # CLI-level coverage for the timeouts block: parsed by validate and the
  # mocked suite on every PR (offline CI job), honoured on --apply runs.
  # Written with `=` (not a block): like every other SingleNestedAttribute
  # in this provider, `timeouts` only accepts the assignment form.
  timeouts = {
    create = "15m"
    delete = "15m"
  }
}

resource "windows_local_group_member" "fixture_svc" {
  group  = windows_local_group.fixture.name
  member = windows_local_user.svc.name

  # CLI-level coverage for the timeouts block (see above).
  timeouts = {
    create = "5m"
    delete = "5m"
  }
}
