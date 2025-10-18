# Windows Hostname Resource

Manages the hostname of a Windows server via SSH and PowerShell remote execution.

## Table of Contents

1. [Example Usage](#example-usage)
2. [Argument Reference](#argument-reference)
3. [Attributes Reference](#attributes-reference)
4. [Advanced Examples](#advanced-examples)
5. [Import](#import)
6. [Troubleshooting](#troubleshooting)

---

## Example Usage

### Basic Usage

```hcl
resource "windows_hostname" "example" {
  hostname = "new-hostname"
}
```

### With Automatic Restart

```hcl
resource "windows_hostname" "example" {
  hostname        = "new-hostname"
  restart         = true
  command_timeout = 300
}
```

### With Custom Timeout

```hcl
resource "windows_hostname" "example" {
  hostname        = "prod-server-01"
  restart         = true
  command_timeout = 600
}
```

---

## Argument Reference

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| **hostname** | string | The new hostname to set for the Windows machine. Must be between 1-15 characters and contain only letters, numbers, and hyphens. Cannot start or end with a hyphen. |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| **restart** | bool | false | Whether to restart the server automatically after changing the hostname. A restart is usually required for the hostname change to take effect. When `true`, the server will reboot without manual intervention. |
| **command_timeout** | number | 300 | Timeout in seconds for PowerShell commands executed on the remote server. |

---

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | The current hostname of the machine. Used as the unique identifier. |
| **current_hostname** | string | The hostname before the change was applied. Useful for tracking what the previous hostname was. |
| **previous_hostname** | string | The hostname that was set before this resource was applied (imported state). |
| **requires_restart** | bool | Whether a restart is required for the hostname change to take effect. |

---

## Advanced Examples

### Hostname with DNS Registration

```hcl
resource "windows_hostname" "web_server" {
  hostname = "web-server-prod-01"
  restart  = true
}

# Optional: Update DNS records after hostname change
resource "aws_route53_record" "web_server" {
  zone_id = aws_route53_zone.example.zone_id
  name    = "web-server-prod-01.example.com"
  type    = "A"
  ttl     = 300
  records = ["192.168.1.100"]

  depends_on = [windows_hostname.web_server]
}
```

### Conditional Hostname Change

```hcl
variable "environment" {
  type    = string
  default = "dev"
}

variable "server_number" {
  type    = number
  default = 1
}

resource "windows_hostname" "server" {
  hostname = "${var.environment}-server-${format("%02d", var.server_number)}"
  restart  = true
}
```

### Multiple Server Hostname Management

```hcl
variable "servers" {
  type = map(object({
    hostname = string
  }))
  default = {
    web1 = { hostname = "web-prod-01" }
    web2 = { hostname = "web-prod-02" }
    db1  = { hostname = "db-prod-01" }
  }
}

resource "windows_hostname" "servers" {
  for_each = var.servers

  hostname = each.value.hostname
  restart  = true
}
```

### Hostname Change with Graceful Shutdown

```hcl
resource "windows_hostname" "example" {
  hostname = "new-hostname"
  restart  = true
}

# Optional: Notify users before restart
resource "null_resource" "notify_users" {
  provisioner "local-exec" {
    command = "echo 'Hostname changed to: ${windows_hostname.example.hostname}'"
  }

  depends_on = [windows_hostname.example]
}
```

### Scheduled Hostname Change

```hcl
resource "windows_hostname" "example" {
  hostname        = "prod-server-renamed"
  restart         = true
  command_timeout = 600  # Allow 10 minutes for graceful shutdown
}

output "old_hostname" {
  value       = windows_hostname.example.previous_hostname
  description = "The previous hostname"
}

output "new_hostname" {
  value       = windows_hostname.example.hostname
  description = "The newly set hostname"
}
```

---

## Import

Windows hostnames can be imported using the current hostname. This allows you to bring existing Windows servers under Terraform management.

### Import Syntax

```shell
terraform import windows_hostname.<resource_name> <current_hostname>
```

### Import Examples

Import a server with hostname "old-server":

```shell
terraform import windows_hostname.example old-server
```

Create the resource configuration first:

```hcl
resource "windows_hostname" "example" {
  hostname = "new-hostname"
  restart  = true
}
```

Then import the existing server:

```shell
terraform import windows_hostname.example old-server
```

### Import Multiple Servers

Create resource definitions:

```hcl
resource "windows_hostname" "server1" {
  hostname = "web-server-01"
  restart  = true
}

resource "windows_hostname" "server2" {
  hostname = "db-server-01"
  restart  = true
}
```

Import the existing hostnames:

```shell
terraform import windows_hostname.server1 current-web-server
terraform import windows_hostname.server2 current-db-server
```

---

## Troubleshooting

### Hostname Change Fails

**Issue**: `hostname change failed` or `unable to rename computer`

**Solutions**:
- Verify the hostname format (1-15 characters, alphanumeric and hyphens only)
- Ensure the new hostname is unique in the network
- Check for reserved or conflicting hostnames
- Verify SSH user has administrator privileges
- Check Windows event logs: `Get-EventLog -LogName System -Newest 20`

### Hostname Not Taking Effect

**Issue**: Hostname changed in PowerShell but not visible in the system

**Solutions**:
- Set `restart = true` to force a system restart
- Manual restart: `Restart-Computer -Force`
- Wait for the restart to complete before accessing the server
- Run `hostname` command to verify the new hostname

### SSH Connection Lost After Restart

**Issue**: Connection drops after hostname change and restart

**Solutions**:
- This is normal behavior. Wait 30-60 seconds for the server to reboot
- Update your Terraform provider configuration with the new hostname if the IP changed
- Use IP addresses instead of hostnames in the provider configuration
- Ensure the SSH user account exists after the rename (usually automatic)

### Permission Denied

**Issue**: `access denied` or `unauthorized` error during hostname change

**Solutions**:
- Verify the SSH user is in the Administrators group
- Check with: `whoami /groups | find "S-1-5-32-544"`
- Local Computer Policy may restrict hostname changes
- Check Group Policy: `gpresult /h report.html`

### Invalid Hostname Characters

**Issue**: `invalid hostname` or character-related errors

**Solutions**:
- Hostname must contain only letters (A-Z, a-z), numbers (0-9), and hyphens (-)
- Cannot start or end with a hyphen
- Maximum length is 15 characters for NetBIOS compatibility (63 for DNS)
- Use lowercase letters for consistency: `new-hostname` (not `NEW-HOSTNAME`)
- Examples of valid hostnames: `web-server-01`, `db01`, `prod-app-srv`

### Hostname Conflict

**Issue**: `hostname already in use` or duplicate hostname error

**Solutions**:
- Ensure the new hostname is unique on the network
- Check DNS and WINS records
- Verify no other servers use the same hostname
- Run network scan: `nslookup <hostname>`
- Check DHCP reservations

### Restart Timeout

**Issue**: Server restart takes too long, timeout occurs

**Solutions**:
- Increase `command_timeout` to allow more time for restart
- Example: `command_timeout = 600` (10 minutes)
- Check server resource usage during restart
- Verify no long-running processes are preventing shutdown
- Check: `Get-Process | Sort-Object -Property CPU -Descending`

### Domain-Joined Server Issues

**Issue**: Cannot change hostname on domain-joined computer

**Solutions**:
- Domain policies may restrict hostname changes
- Administrator with domain privileges may be required
- Check Group Policy: `gpresult /h report.html`
- Contact domain administrator for policy exceptions
- May require offline rename through domain controller

### State Mismatch

**Issue**: Terraform state differs from actual hostname

**Solutions**:
- Manually changed hostname outside of Terraform
- Run `terraform refresh` to update state
- Or: `terraform import windows_hostname.example <current_hostname>`
- Always use Terraform for hostname changes to keep state in sync

---

## Best Practices

### Hostname Naming Convention

Use a consistent naming convention for easy identification:

```hcl
# Example naming scheme: <environment>-<role>-<number>
resource "windows_hostname" "web_prod" {
  hostname = "prod-web-01"  # Production web server #1
  restart  = true
}

resource "windows_hostname" "db_staging" {
  hostname = "stag-db-01"   # Staging database server #1
  restart  = true
}
```

### Always Plan Before Applying

Hostname changes are significant infrastructure modifications:

```bash
terraform plan  # Review the changes
terraform apply # Apply only after verification
```

### Document Hostname Changes

```hcl
resource "windows_hostname" "web_server" {
  hostname = "prod-web-01"
  restart  = true

  tags = {
    Name        = "Production Web Server"
    Environment = "Production"
    Purpose     = "Web hosting"
    ManagedBy   = "Terraform"
  }
}
```

### Use Variables for Environment-Specific Names

```hcl
variable "hostname_prefix" {
  type        = string
  description = "Prefix for hostname (e.g., prod, dev, staging)"
}

resource "windows_hostname" "example" {
  hostname = "${var.hostname_prefix}-server-01"
  restart  = true
}
```

### Coordinate with Other Infrastructure

```hcl
# Ensure DNS is updated before hostname change is complete
resource "windows_hostname" "server" {
  hostname = "new-hostname"
  restart  = true
}

resource "route53_record" "server" {
  zone_id = aws_route53_zone.example.zone_id
  name    = "${windows_hostname.server.hostname}.example.com"
  type    = "A"
  ttl     = 300
  records = ["192.168.1.100"]

  depends_on = [windows_hostname.server]
}
```

---

## Limitations

- **Restart Required**: Hostname changes typically require a server restart to take full effect
- **No Rollback**: Once applied, the hostname change is permanent until another change is made
- **Single Change**: Only one hostname can be set per resource instance
- **DNS Updates**: Ensure DNS records are updated separately if needed
- **Domain Membership**: Domain-joined computers may have additional restrictions based on Group Policy

---

## Additional Resources

- [Windows Hostname Requirements (Microsoft Docs)](https://docs.microsoft.com/en-us/windows-server/)
- [Group Policy for Hostname Management](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/group-policy-and-windows-update)
- [PowerShell Rename-Computer Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/rename-computer)