# Local group + local user + membership, wired together the way a real
# configuration would: the group is the privilege boundary, the user is a
# service account, and the member resource is the join between them. This
# combination is what caught the original local_group_member SID-vs-name
# convergence issues that single-resource unit tests could not reach.
#
# The password is deliberately unrelated to both the account name and the
# full name: Windows' complexity filter rejects a password containing three
# or more consecutive characters of either, and `svc-app-${var.test_suffix}`
# would otherwise collide with the trailing `pushed` token.
resource "windows_local_group" "app_operators" {
  name        = "AppOperators-${var.test_suffix}"
  description = "Operators allowed to run the AppSuite service (lab-container pushed test)."
}

resource "windows_local_user" "svc_app" {
  name                         = "svc-app-${var.test_suffix}"
  full_name                    = "AppSuite Service Account"
  description                  = "Runs the pushed-test fixture task and service."
  password_wo                  = "Xk7!mQ2#nR9w"
  password_wo_version          = 1
  enabled                      = true
  password_never_expires       = true
  user_may_not_change_password = true
  account_never_expires        = true
}

# Non-authoritative: only this (group, member) pair is managed, so this
# fixture can cohabit a shared container with other out-of-band memberships.
resource "windows_local_group_member" "app_operators_svc_app" {
  group  = windows_local_group.app_operators.name
  member = windows_local_user.svc_app.name
}
