# windows_hostname

Manages the hostname of a Windows server.

## Example Usage

### Basic Hostname Configuration

```hcl
resource "windows_hostname" "server" {
  hostname = "WEB-SERVER-01"
}
```

### Hostname with Automatic Restart

```hcl
resource "windows_hostname" "server" {
  hostname = "WEB-SERVER-01"
  restart  = true
}
```

### FQDN Hostname

```hcl
resource "windows_hostname" "server" {
  hostname = "web01.domain.local"
}
```

### With Custom Timeout

```hcl
resource "windows_hostname" "server" {
  hostname        = "APP-SERVER-02"
  restart         = true
  command_timeout = 600
}
```

## Argument Reference

The following arguments are supported:

* `hostname` - (Required, String) The new hostname to apply to the Windows machine. The hostname must follow these rules:
  - Maximum 255 characters total
  - Each label (part between dots) maximum 63 characters
  - Labels can contain letters, digits, and hyphens
  - Labels cannot start or end with a hyphen
  - Case-insensitive

* `restart` - (Optional, Boolean) Restart the computer after renaming. Default: `false`. 
  ⚠️ **Warning**: Setting this to `true` will cause the server to restart immediately, which will disconnect the SSH session.

* `command_timeout` - (Optional, Number) Timeout in seconds for PowerShell commands. Default: `300` (5 minutes).

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The hostname.

## Import

Windows hostname can be imported using the hostname:

```bash
terraform import windows_hostname.server WEB-SERVER-01
```

## Hostname Naming Conventions

### NetBIOS Names (Single Label)

For standalone or workgroup computers, use a NetBIOS name:
- Maximum 15 characters (16th is reserved by Windows)
- Letters, digits, and hyphens only
- Cannot start or end with hyphen
- Case-insensitive

Examples:
- `WEB-SERVER-01`
- `APP-01`
- `DC-PRIMARY`

### Fully Qualified Domain Names (FQDN)

For domain-joined computers, you can use FQDN:
- Multiple labels separated by dots
- Each label follows NetBIOS rules
- Total length maximum 255 characters

Examples:
- `web01.contoso.com`
- `app-server.prod.domain.local`
- `dc01.ad.company.net`

## Restart Behavior

When `restart = true`:

1. The hostname change command includes `-Restart` flag
2. The server will reboot immediately after the command executes
3. The SSH connection will be lost
4. Terraform will complete the operation before the reboot finishes

⚠️ **Important Considerations**:
- Ensure you have another way to connect to the server after restart
- The server's IP address should not change
- Consider using out-of-band management (iDRAC, iLO, etc.) for monitoring
- Allow sufficient time for the server to complete the reboot

When `restart = false`:
- The hostname change is applied but won't take effect until manual reboot
- The old hostname will still be active
- You'll need to restart manually: `Restart-Computer -Force`

## DNS and Domain Considerations

### Standalone/Workgroup Servers

Changing hostname on standalone servers is straightforward:

```hcl
resource "windows_hostname" "standalone" {
  hostname = "NEW-SERVER"
  restart  = true
}
```

### Domain-Joined Servers

⚠️ **Important**: Changing the hostname of a domain-joined server requires additional steps:

1. The computer must be removed from the domain first
2. Change the hostname
3. Re-join the domain with the new name

This provider currently handles only the hostname change. For domain operations, you may need to:
- Manually unjoin/rejoin the domain
- Use additional automation tools
- Coordinate with domain administrators

### DNS Updates

After changing hostname:
- Dynamic DNS (DDNS) should update automatically if enabled
- Static DNS records must be updated manually
- DHCP reservations may need updating
- Update any monitoring systems, scripts, or documentation

## Validation

The provider validates hostname format before applying:

✅ **Valid hostnames**:
```
WEB-SERVER-01
app-server
DC01
web01.domain.local
server-2024-prod
```

❌ **Invalid hostnames**:
```
-invalid        # starts with hyphen
invalid-       # ends with hyphen
my_server      # contains underscore
server 01      # contains space
thisisaverylonghostnamethathastoomanycharacterstobevalidforanetbiosname  # > 63 chars per label
```

## Common Use Cases

### Standardized Naming Convention

```hcl
locals {
  environment = "prod"
  role        = "web"
  instance    = "01"
  hostname    = upper("${var.environment}-${var.role}-${var.instance}")
}

resource "windows_hostname" "server" {
  hostname = local.hostname  # PROD-WEB-01
}
```

### Sequential Server Naming

```hcl
variable "server_count" {
  default = 3
}

resource "windows_hostname" "servers" {
  count    = var.server_count
  hostname = upper("WEB-SERVER-${format("%02d", count.index + 1)}")
}
# Creates: WEB-SERVER-01, WEB-SERVER-02, WEB-SERVER-03
```

## Troubleshooting

### Hostname Doesn't Change

**Issue**: Resource applies successfully but hostname doesn't change

**Solution**:
- Restart the server: `Restart-Computer -Force`
- Or set `restart = true` in the resource

### Permission Denied

**Issue**: `Access is denied` or `You do not have sufficient privileges`

**Solution**:
- The SSH user must have administrator rights
- Verify: `whoami /groups | find "S-1-5-32-544"`

### Hostname Conflict

**Issue**: New hostname conflicts with existing DNS records

**Solution**:
- Check DNS for conflicts: `nslookup NEW-HOSTNAME`
- Remove or update conflicting DNS records
- Update DHCP reservations if needed

### Invalid Hostname Error

**Issue**: `invalid hostname` error during plan/apply

**Solution**:
- Check hostname follows naming rules
- No special characters except hyphen
- No leading or trailing hyphens
- Maximum 63 characters per label

## Notes

- Hostname changes are case-insensitive
- The provider performs case-insensitive comparison during read operations
- Changing hostname may affect Active Directory, DNS, certificates, and monitoring systems
- Plan downtime appropriately when using `restart = true`
- Update all references to the old hostname (scripts, documentation, DNS, etc.)

## Security Considerations

- Administrator privileges required
- Hostname changes are logged in Windows Event Log
- Consider impact on security policies and GPOs
- Certificates with hostname in CN/SAN may need reissuing
- Kerberos tickets may need to be refreshed
