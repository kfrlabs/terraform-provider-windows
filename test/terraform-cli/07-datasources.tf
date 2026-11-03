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

  # CLI-level coverage for the data source timeouts block (issue #197):
  # parsed by validate and the mock test run. SingleNestedAttribute in
  # this provider, `timeouts` only accepts the assignment form.
  timeouts = {
    read = "5m"
  }
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

# One data source per newly covered resource below. Each mirrors its
# resource's gate; data referencing managed objects needs an explicit
# depends_on only where the reference is not an implicit dependency (see
# windows_local_group_member above).

data "windows_directory" "app_logs" {
  path = windows_directory.app_logs.path
}

data "windows_file" "app_config" {
  path = windows_file.app_config.path
}

data "windows_file_acl" "app_config" {
  path = windows_file.app_config.path
}

data "windows_firewall_profile" "fixture" {
  count = var.enable_firewall_tests ? 1 : 0

  name = windows_firewall_profile.fixture[0].name
}

data "windows_dns_client" "secondary" {
  count = var.enable_network_config_tests ? 1 : 0

  interface_alias = windows_dns_client.secondary[0].interface_alias
}

data "windows_net_ip_address" "storage" {
  count = var.enable_network_config_tests ? 1 : 0

  ip_address      = windows_net_ip_address.storage[0].ip_address
  interface_alias = windows_net_ip_address.storage[0].interface_alias
}

data "windows_net_route" "backup" {
  count = var.enable_network_config_tests ? 1 : 0

  destination_prefix = windows_net_route.backup[0].destination_prefix
  interface_alias    = windows_net_route.backup[0].interface_alias
  next_hop           = windows_net_route.backup[0].next_hop
}

data "windows_smb_share" "fixture" {
  count = var.enable_smb_tests ? 1 : 0

  name = windows_smb_share.fixture[0].name
}

data "windows_certificate" "fixture" {
  count = var.enable_certificate_tests ? 1 : 0

  thumbprint = windows_certificate.fixture[0].thumbprint
}

data "windows_legacy_package" "sevenzip" {
  count = var.enable_network_tests ? 1 : 0

  product_id = windows_legacy_package.sevenzip[0].product_id
}
