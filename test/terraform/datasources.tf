# One data source per sibling resource above, cross-checked against the
# resource's own state. Data sources share the resource's winclient Read
# path (see CLAUDE.md), so divergence here usually points at a Read-vs-Create
# state mismatch rather than a data-source-only bug.
#
# Attribute names differ from the resource in a couple of places on purpose
# (e.g. windows_local_group_member exposes group_name/member_name, not
# group/member); this file is what pins that mapping down.

data "windows_local_group" "app_operators" {
  name = windows_local_group.app_operators.name
}

data "windows_local_user" "svc_app" {
  name = windows_local_user.svc_app.name
}

data "windows_local_group_member" "app_operators_svc_app" {
  group_name  = windows_local_group.app_operators.name
  member_name = windows_local_user.svc_app.name
}

data "windows_registry_value" "app_version" {
  hive = windows_registry_value.app_version.hive
  path = windows_registry_value.app_version.path
  name = windows_registry_value.app_version.name
}

data "windows_environment_variable" "app_home" {
  name  = windows_environment_variable.app_home.name
  scope = windows_environment_variable.app_home.scope
}

data "windows_firewall_rule" "allow_app_inbound" {
  name = windows_firewall_rule.allow_app_inbound.name
}

data "windows_scheduled_task" "pushed_test" {
  name = windows_scheduled_task.pushed_test.name
  path = windows_scheduled_task.pushed_test.path
}

data "windows_service" "pushed_test" {
  name = windows_service.pushed_test.name
}

data "windows_hostname" "current" {}

data "windows_feature" "web_server" {
  count = var.enable_feature_test ? 1 : 0
  name  = "Web-Server"
}
