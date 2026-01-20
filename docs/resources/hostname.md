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
resource "windows_hostname" "server_auto_restart" {
  hostname = "DB-SERVER-01"
  restart  = true
}
```

### Hostname with Custom Timeout

```hcl
resource "windows_hostname" "server_custom" {
  hostname        = "APP-SERVER-01"
  command_timeout = 600
}
```

## Argument Reference

The following arguments are supported:

* `hostname` - (Required) The new hostname to apply to the Windows machine. Must follow DNS hostname rules:
  - Maximum 255 characters total length
  - Each label (part between dots) maximum 63 characters
  - Labels can contain letters, digits, and hyphens
  - Labels cannot start or end with a hyphen
  - Can be a simple name (e.g., `SERVER01`) or FQDN (e.g., `server01.domain.local`)
* `restart` - (Optional) Whether to restart the computer after renaming. Defaults to `false`. **Important:** A restart is required for the hostname change to take effect.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300` (5 minutes).

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The hostname.
* `pending_reboot` - (Boolean) Indicates if a reboot is pending for the hostname change to take effect. This will be `true` if `restart = false` after creation/update, and will be set to `false` once a restart has been performed.

## Import

Hostnames can be imported using the hostname value:

```shell
terraform import windows_hostname.server "WEB-SERVER-01"
```

## Behavior Notes

### Restart Requirements

**Important:** Changing a Windows hostname requires a system restart to take full effect.

- If `restart = true`: The computer will restart automatically after the hostname is changed. The SSH connection will be lost during the restart.
- If `restart = false` (default): The hostname change is applied but will not take effect until the computer is manually restarted. The `pending_reboot` attribute will be set to `true`.

### Existing Hostname Detection

When creating the resource:
- If the current hostname already matches the target hostname, no change is made and no restart is required.
- The comparison is case-insensitive (Windows hostnames are case-insensitive).

### Read Behavior with Pending Reboot

If a reboot is pending (`pending_reboot = true`):
- The Read operation will tolerate the hostname mismatch, as the change hasn't taken effect yet.
- Once the computer is restarted, the next Read will detect the new hostname and clear the `pending_reboot` flag.

### Delete Behavior

The delete operation removes the resource from Terraform state but **does not change the hostname** on the remote server. This is by design, as reverting a hostname could cause service disruptions.

## Hostname Validation

The resource validates hostnames according to DNS standards:

### Valid Hostnames
```hcl
hostname = "SERVER01"              # Simple NetBIOS name
hostname = "web-server-01"         # Name with hyphens
hostname = "app.domain.local"      # Fully qualified domain name
hostname = "db01.subdomain.company.com"  # Multi-level FQDN
```

### Invalid Hostnames
```hcl
hostname = "-webserver"            # Cannot start with hyphen
hostname = "webserver-"            # Cannot end with hyphen
hostname = "web_server"            # Underscores not allowed
hostname = "a.very.long.hostname.that.exceeds.the.maximum.length.of.255.characters..."  # Too long
hostname = "label-that-is-way-too-long-and-exceeds-sixty-three-characters-limit"  # Label too long
```

## Example: Managed Restart Workflow

```hcl
# Change hostname without automatic restart
resource "windows_hostname" "app_server" {
  hostname = "APP-SERVER-NEW"
  restart  = false
}

# Output warns about pending restart
output "reboot_required" {
  value = windows_hostname.app_server.pending_reboot
}

# You can then manually restart the server when ready:
# Restart-Computer -Force
```

## Example: Automatic Restart

```hcl
# Change hostname with automatic restart
resource "windows_hostname" "web_server" {
  hostname = "WEB-PROD-01"
  restart  = true
}

# Note: Terraform execution may be interrupted during restart
# This is expected behavior
```