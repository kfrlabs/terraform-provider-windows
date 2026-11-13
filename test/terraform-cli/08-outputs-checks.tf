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

output "firewall_profile_name" {
  value       = var.enable_firewall_tests ? windows_firewall_profile.fixture[0].name : "disabled"
  description = "Name of the tuned firewall profile ('disabled' when firewall tests are off)."
}

output "smb_share_name" {
  value       = var.enable_smb_tests ? windows_smb_share.fixture[0].name : "disabled"
  description = "Name of the fixture SMB share ('disabled' when SMB tests are off)."
}

output "certificate_thumbprint" {
  value       = var.enable_certificate_tests ? windows_certificate.fixture[0].thumbprint : "disabled"
  description = "Thumbprint of the imported fixture certificate ('disabled' when certificate tests are off)."
}

output "domain_pending_reboot" {
  value       = var.enable_domain_membership_test ? windows_domain_membership.fixture[0].pending_reboot : false
  description = "True when the domain join left the host reboot-pending (false when the domain test is off)."
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
  sensitive = true
}

output "check_registry_dword" {
  value = {
    resource = windows_registry_value.max_retries.value_string
    data     = data.windows_registry_value.max_retries.value_string
  }
  sensitive = true
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

output "check_directory" {
  value = {
    resource = windows_directory.app_logs.item_count
    data     = data.windows_directory.app_logs.item_count
  }
}

output "check_file" {
  value = {
    resource = windows_file.app_config.content_sha256
    data     = data.windows_file.app_config.content_sha256
  }
}

output "check_file_acl" {
  value = {
    resource = windows_file_acl.app_config.sddl
    data     = data.windows_file_acl.app_config.sddl
  }
}

output "check_firewall_profile" {
  value = var.enable_firewall_tests ? {
    resource = windows_firewall_profile.fixture[0].enabled
    data     = data.windows_firewall_profile.fixture[0].enabled
  } : null
}

output "check_dns" {
  value = var.enable_network_config_tests ? {
    resource = windows_dns_client.secondary[0].effective_ipv4
    data     = data.windows_dns_client.secondary[0].effective_ipv4
  } : null
}

output "check_net_ip" {
  value = var.enable_network_config_tests ? {
    resource = windows_net_ip_address.storage[0].address_state
    data     = data.windows_net_ip_address.storage[0].address_state
  } : null
}

output "check_net_route" {
  value = var.enable_network_config_tests ? {
    resource = windows_net_route.backup[0].effective_metric
    data     = data.windows_net_route.backup[0].effective_metric
  } : null
}

output "check_smb_share" {
  value = var.enable_smb_tests ? {
    resource = windows_smb_share.fixture[0].special
    data     = data.windows_smb_share.fixture[0].special
  } : null
}

output "check_certificate" {
  value = var.enable_certificate_tests ? {
    resource = windows_certificate.fixture[0].thumbprint
    data     = data.windows_certificate.fixture[0].thumbprint
  } : null
}

output "check_legacy_package" {
  value = var.enable_network_tests ? {
    resource = windows_legacy_package.sevenzip[0].installed
    data     = data.windows_legacy_package.sevenzip[0].installed
  } : null
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

check "directory_agrees" {
  assert {
    condition     = data.windows_directory.app_logs.item_count == windows_directory.app_logs.item_count
    error_message = "windows_directory data source disagrees with the resource."
  }
}

check "file_agrees" {
  assert {
    condition     = data.windows_file.app_config.content_sha256 == windows_file.app_config.content_sha256
    error_message = "windows_file data source disagrees with the resource."
  }
}

check "file_acl_agrees" {
  assert {
    condition     = data.windows_file_acl.app_config.sddl == windows_file_acl.app_config.sddl
    error_message = "windows_file_acl data source disagrees with the resource."
  }
}

# Gated pairs: vacuously true while the gate is off (no instances to
# compare), enforced once the fixtures are enabled.
check "firewall_profile_agrees" {
  assert {
    condition     = !var.enable_firewall_tests || data.windows_firewall_profile.fixture[0].enabled == windows_firewall_profile.fixture[0].enabled
    error_message = "windows_firewall_profile data source disagrees with the resource."
  }
}

check "dns_agrees" {
  assert {
    condition     = !var.enable_network_config_tests || data.windows_dns_client.secondary[0].effective_ipv4 == windows_dns_client.secondary[0].effective_ipv4
    error_message = "windows_dns_client data source disagrees with the resource."
  }
}

check "net_ip_agrees" {
  assert {
    condition     = !var.enable_network_config_tests || data.windows_net_ip_address.storage[0].address_state == windows_net_ip_address.storage[0].address_state
    error_message = "windows_net_ip_address data source disagrees with the resource."
  }
}

check "net_route_agrees" {
  assert {
    condition     = !var.enable_network_config_tests || data.windows_net_route.backup[0].effective_metric == windows_net_route.backup[0].effective_metric
    error_message = "windows_net_route data source disagrees with the resource."
  }
}

check "smb_share_agrees" {
  assert {
    condition     = !var.enable_smb_tests || data.windows_smb_share.fixture[0].special == windows_smb_share.fixture[0].special
    error_message = "windows_smb_share data source disagrees with the resource."
  }
}

check "certificate_agrees" {
  assert {
    condition     = !var.enable_certificate_tests || data.windows_certificate.fixture[0].thumbprint == windows_certificate.fixture[0].thumbprint
    error_message = "windows_certificate data source disagrees with the resource."
  }
}

check "legacy_package_agrees" {
  assert {
    condition     = !var.enable_network_tests || data.windows_legacy_package.sevenzip[0].installed == windows_legacy_package.sevenzip[0].installed
    error_message = "windows_legacy_package data source disagrees with the resource."
  }
}
