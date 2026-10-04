output "local_group_sid" {
  value       = windows_local_group.fixture.sid
  description = "SID Windows assigned to the fixture group."
}

output "local_user_sid" {
  value       = windows_local_user.svc.sid
  description = "SID Windows assigned to the fixture service account."
}

output "membership_id" {
  value       = windows_local_group_member.fixture_svc.id
  description = "Composite <group_sid>/<member_sid> id of the managed membership."
}

output "file_path" {
  value = windows_file.app_config.path
}

output "file_content_sha256" {
  value = windows_file.app_config.content_sha256
}

output "file_acl_sddl" {
  value = windows_file_acl.app_config.sddl
}

output "firewall_rule_name" {
  value       = var.enable_firewall_tests ? windows_firewall_rule.allow_inbound[0].name : "disabled"
  description = "Name of the created inbound firewall rule ('disabled' when firewall tests are off)."
}

output "service_name" {
  value = windows_service.fixture.name
}

output "scheduled_task_id" {
  value = windows_scheduled_task.fixture.id
}

# Resource vs data source cross-checks — a mismatch is a real finding.
output "check_registry_value" {
  value = {
    resource = windows_registry_value.version.value_string
    data     = data.windows_registry_value.version.value_string
  }
}

output "check_registry_dword" {
  value = {
    resource = windows_registry_value.max_retries.value_string
    data     = data.windows_registry_value.max_retries.value_string
  }
}

output "check_local_user_sid" {
  value = {
    resource = windows_local_user.svc.sid
    data     = data.windows_local_user.svc.sid
  }
}

output "check_group_member_sid" {
  value = {
    resource = windows_local_group_member.fixture_svc.member_sid
    data     = data.windows_local_group_member.fixture_svc.member_sid
  }
}

output "check_env_var" {
  value = {
    resource = windows_environment_variable.app_home.value
    data     = data.windows_environment_variable.app_home.value
  }
}

output "hostname" {
  value = {
    current_name   = data.windows_hostname.current.current_name
    reboot_pending = data.windows_hostname.current.reboot_pending
  }
}

# Post-apply assertions: `terraform apply` fails if any check is false.
check "registry_value_agrees" {
  assert {
    condition     = data.windows_registry_value.version.value_string == windows_registry_value.version.value_string
    error_message = "windows_registry_value data source disagrees with the resource."
  }
}

check "local_user_sid_agrees" {
  assert {
    condition     = data.windows_local_user.svc.sid == windows_local_user.svc.sid
    error_message = "windows_local_user data source SID disagrees with the resource."
  }
}

check "group_member_sid_agrees" {
  assert {
    condition     = data.windows_local_group_member.fixture_svc.member_sid == windows_local_group_member.fixture_svc.member_sid
    error_message = "windows_local_group_member data source SID disagrees with the resource."
  }
}

check "env_var_agrees" {
  assert {
    condition     = data.windows_environment_variable.app_home.value == windows_environment_variable.app_home.value
    error_message = "windows_environment_variable data source disagrees with the resource."
  }
}
