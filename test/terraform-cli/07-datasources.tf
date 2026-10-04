# One data source per resource above, cross-checked against the resource's
# own state. Divergence here means the data source Read disagrees with the
# resource Read for the same object.

data "windows_local_group" "fixture" {
  name = windows_local_group.fixture.name
}

data "windows_local_user" "svc" {
  name = windows_local_user.svc.name
}

data "windows_local_group_member" "fixture_svc" {
  group_name  = windows_local_group.fixture.name
  member_name = windows_local_user.svc.name

  # Read-after-write ordering: without this, Terraform may read the data
  # source as soon as the group+user exist but before this exact membership
  # is added, failing with "member not found". The data source only
  # references the group/user names, so the member resource is not an
  # implicit dependency.
  depends_on = [windows_local_group_member.fixture_svc]
}

data "windows_registry_value" "version" {
  hive = windows_registry_value.version.hive
  path = windows_registry_value.version.path
  name = windows_registry_value.version.name
}

data "windows_registry_value" "max_retries" {
  hive = windows_registry_value.max_retries.hive
  path = windows_registry_value.max_retries.path
  name = windows_registry_value.max_retries.name
}

data "windows_environment_variable" "app_home" {
  name  = windows_environment_variable.app_home.name
  scope = windows_environment_variable.app_home.scope
}

data "windows_environment_variable" "user_token" {
  name  = windows_environment_variable.user_token.name
  scope = windows_environment_variable.user_token.scope
}

data "windows_firewall_rule" "allow_inbound" {
  count = var.enable_firewall_tests ? 1 : 0

  name = windows_firewall_rule.allow_inbound[0].name
}

data "windows_scheduled_task" "fixture" {
  name = windows_scheduled_task.fixture.name
  path = windows_scheduled_task.fixture.path
}

data "windows_service" "fixture" {
  name = windows_service.fixture.name
}

data "windows_hostname" "current" {}

data "windows_feature" "web_server" {
  count = var.enable_feature_test ? 1 : 0
  name  = "Web-Server"
}

data "windows_winget_package" "vscode" {
  count = var.enable_network_tests ? 1 : 0

  package_id = "Microsoft.VisualStudioCode"
  source     = "winget"
}
