# Terraform Provider for Windows

## Example Usage

```hcl
provider "tf-windows" {
  host          = "192.168.1.1"
  username      = "admin"
  password      = "password"
  key_path      = "/path/to/private/key"
  use_ssh_agent = false
  conn_timeout  = 30
}
```

## Argument Reference

- **host** (Required) - The hostname or IP address of the Windows server.
- **username** (Required) - The username for SSH authentication.
- **password** (Optional) - The password for SSH authentication. Required if `use_ssh_agent` is false.
- **key_path** (Optional) - The path to the private key for SSH authentication.
- **use_ssh_agent** (Optional) - Whether to use the SSH agent for authentication.
- **conn_timeout** (Optional) - Timeout in seconds for SSH connection.

## Resources

- **tf-windows_feature** - Manages Windows features.
- **tf-windows_registry_key** - Manages Windows registry keys.
- **tf-windows_registry_value** - Manages Windows registry values. 