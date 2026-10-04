# Identity: group + user + membership wired together (realistic pattern).
#
# NOTE: windows_local_user uses legacy `password` (not `password_wo`) on
# purpose: `password_wo` never reaches Create — the framework nullifies
# write-only attributes in the plan handed to ApplyResourceChange, and the
# provider reads the password from req.Plan instead of req.Config, so Create
# always fails with "password is required at Create time" (issue #99, see
# README). The Go acceptance suite uses `password` too. Migrate back to
# `password_wo` once the provider reads write-only values from req.Config.
resource "windows_local_group" "fixture" {
  name        = "CliOperators-${var.test_suffix}"
  description = "terraform-cli fixture group - safe to delete."
}

resource "windows_local_user" "svc" {
  name                         = "svc-cli-${var.test_suffix}"
  full_name                    = "CLI Fixture Service Account"
  description                  = "Runs the terraform-cli fixture task."
  password                     = var.svc_password
  enabled                      = true
  password_never_expires       = true
  user_may_not_change_password = true
  account_never_expires        = true
}

resource "windows_local_group_member" "fixture_svc" {
  group  = windows_local_group.fixture.name
  member = windows_local_user.svc.name
}
