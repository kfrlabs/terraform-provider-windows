# windows_localgroupmembers (Data Source)

Retrieves the list of members belonging to a local group on a Windows server.

## Example Usage

### List Administrators

```hcl
data "windows_localgroupmembers" "admins" {
  group_name = "Administrators"
}

output "admin_count" {
  value = data.windows_localgroupmembers.admins.member_count
}

output "admin_members" {
  value = data.windows_localgroupmembers.admins.members
}
```

### Query Specific Group Members

```hcl
data "windows_localgroupmembers" "rdp_users" {
  group_name = "Remote Desktop Users"
}

output "rdp_user_names" {
  value = [
    for member in data.windows_localgroupmembers.rdp_users.members : member.name
  ]
}
```

### Filter Members by Type

```hcl
data "windows_localgroupmembers" "users" {
  group_name = "Users"
}

locals {
  local_users = [
    for member in data.windows_localgroupmembers.users.members : member
    if member.principal_source == "Local"
  ]
  
  domain_users = [
    for member in data.windows_localgroupmembers.users.members : member
    if member.principal_source == "ActiveDirectory"
  ]
}

output "local_users_count" {
  value = length(local.local_users)
}

output "domain_users_count" {
  value = length(local.domain_users)
}
```

### Check if Specific User is Member

```hcl
data "windows_localgroupmembers" "admins" {
  group_name = "Administrators"
}

locals {
  is_admin = contains(
    [for member in data.windows_localgroupmembers.admins.members : member.name],
    "MyUser"
  )
}

output "user_is_admin" {
  value = local.is_admin
}
```

## Argument Reference

The following arguments are supported:

* `group_name` - (Required) The name of the local group to retrieve members from.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300`.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The group name.
* `member_count` - Number of members in the group.
* `members` - List of group members. Each member has the following attributes:
  * `name` - Name of the member (may include domain prefix, e.g., `DOMAIN\User`).
  * `object_class` - Object class (e.g., `User`, `Group`).
  * `sid` - Security Identifier (SID) of the member.
  * `principal_source` - Source of the principal (e.g., `Local`, `ActiveDirectory`, `AzureAD`).

## Notes

* If the group has no members, the `members` list will be empty and `member_count` will be `0`.
* Member names may include the domain or computer name prefix (e.g., `COMPUTERNAME\Username` or `DOMAIN\Username`).
* The `principal_source` attribute helps identify whether members are local accounts, domain accounts, or Azure AD accounts.

## Error Handling

If the specified group does not exist, the data source will return an error.
