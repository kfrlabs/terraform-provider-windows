# Windows Hostname

## Example Usage

```hcl
resource "windows_hostname" "example" {
  hostname         = "new-hostname"
  restart         = true
  command_timeout = 300
}
```

## Argument Reference

- **hostname** (Required) - The new hostname to set for the Windows machine.
- **restart** (Optional) - Whether to restart the server automatically after changing the hostname.
- **command_timeout** (Optional) - Timeout in seconds for PowerShell commands.

## Import

Windows hostnames can be imported using the current hostname, e.g.

```shell
$ terraform import