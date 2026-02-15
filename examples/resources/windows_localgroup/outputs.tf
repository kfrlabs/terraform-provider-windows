# Export group information
output "developers_group_sid" {
  description = "SID of the developers group"
  value       = windows_localgroup.developers.sid
}

output "custom_groups" {
  description = "Custom groups information"
  value = {
    webapp_users = {
      name = windows_localgroup.webapp_users.name
      sid  = windows_localgroup.webapp_users.sid
    }
    webapp_admins = {
      name = windows_localgroup.webapp_admins.name
      sid  = windows_localgroup.webapp_admins.sid
    }
  }
}

output "security_groups_sids" {
  description = "SIDs of all security level groups"
  value = {
    level1 = windows_localgroup.level1_access.sid
    level2 = windows_localgroup.level2_access.sid
    level3 = windows_localgroup.level3_access.sid
  }
}

output "environment_groups_info" {
  description = "Information about environment groups"
  value = {
    for k, v in windows_localgroup.environment_groups : k => {
      sid              = v.sid
      principal_source = v.principal_source
      description      = v.description
    }
  }
}