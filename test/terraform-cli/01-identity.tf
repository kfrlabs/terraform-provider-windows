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
}

resource "windows_local_group_member" "fixture_svc" {
  group  = windows_local_group.fixture.name
  member = windows_local_user.svc.name
}
