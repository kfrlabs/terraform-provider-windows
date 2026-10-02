# Everything worth eyeballing after `terraform apply`: computed IDs/SIDs the
# resources assign, and the cross-checks between a resource and its sibling
# data source (they should agree).

output "local_group_sid" {
  value       = windows_local_group.app_operators.sid
  description = "SID Windows assigned to the fixture group."
}

output "local_user_sid" {
  value       = windows_local_user.svc_app.sid
  description = "SID Windows assigned to the fixture service account."
}

output "membership_is_present" {
  value       = windows_local_group_member.app_operators_svc_app.id
  description = "Composite <group_sid>/<member_sid> id of the managed membership."
}

output "file_path" {
  value       = windows_file.app_config.path
  description = "Path of the written configuration file."
}

output "file_content_sha256" {
  value       = windows_file.app_config.content_sha256
  description = "Provider-computed hash of the file content."
}

output "file_acl_sddl" {
  value       = windows_file_acl.app_config.sddl
  description = "Observed security descriptor of the secured file."
}

output "file_acl_effective_rules" {
  value = [
    for rule in windows_file_acl.app_config.effective_access_rules :
    "${rule.identity}: ${rule.type} ${join(",", rule.rights)} inherited=${rule.inherited}"
  ]
  description = "Every DACL entry on the file, inherited entries included."
}

output "firewall_rule_name" {
  value       = windows_firewall_rule.allow_app_inbound.name
  description = "Name of the created inbound firewall rule."
}

output "service_name" {
  value       = windows_service.pushed_test.name
  description = "Short name of the created fixture service."
}

output "scheduled_task_id" {
  value       = windows_scheduled_task.pushed_test.id
  description = "Composite id of the created scheduled task."
}

# --- resource vs data source cross-checks -------------------------------
# A mismatch here means the data source's Read disagrees with the resource's
# own state for the same object — exactly the class of bug these fixtures
# exist to surface.

output "check_registry_value" {
  value = {
    resource = windows_registry_value.app_version.value_string
    data     = data.windows_registry_value.app_version.value_string
  }
  description = "windows_registry_value resource vs data source value_string."
}

output "check_local_user_sid" {
  value = {
    resource = windows_local_user.svc_app.sid
    data     = data.windows_local_user.svc_app.sid
  }
  description = "windows_local_user resource vs data source SID."
}

output "check_group_member_sid" {
  value = {
    resource = windows_local_group_member.app_operators_svc_app.member_sid
    data     = data.windows_local_group_member.app_operators_svc_app.member_sid
  }
  description = "windows_local_group_member resource vs data source member SID."
}

output "hostname" {
  value = {
    current_name   = data.windows_hostname.current.current_name
    reboot_pending = data.windows_hostname.current.reboot_pending
  }
  description = "windows_hostname data source view of the container."
}
