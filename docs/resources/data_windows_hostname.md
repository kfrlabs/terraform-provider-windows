# windows_hostname (Data Source)

Retrieves hostname and domain information from a Windows server.

## Example Usage

### Basic Hostname Query

```hcl
data "windows_hostname" "current" {}

output "computer_name" {
  value = data.windows_hostname.current.computer_name
}

output "fqdn" {
  value = data.windows_hostname.current.fqdn
}
```

### Check Domain Membership

```hcl
data "windows_hostname" "current" {}

output "domain_info" {
  value = data.windows_hostname.current.part_of_domain ? {
    domain = data.windows_hostname.current.domain
    fqdn   = data.windows_hostname.current.fqdn
  } : {
    workgroup = data.windows_hostname.current.workgroup
    computer  = data.windows_hostname.current.computer_name
  }
}
```

### Use in Resource Configuration

```hcl
data "windows_hostname" "current" {}

resource "windows_registry_value" "server_name" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "ServerName"
  value = data.windows_hostname.current.fqdn
  type  = "String"
}
```

## Argument Reference

The following arguments are supported:

* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300`.

## Attribute Reference

The following attributes are exported:

* `id` - The computer name.
* `computer_name` - The computer name (NetBIOS name).
* `dns_hostname` - The fully qualified DNS hostname.
* `domain` - The domain name if the computer is part of a domain.
* `workgroup` - The workgroup name if the computer is part of a workgroup.
* `part_of_domain` - Whether the computer is part of a domain (boolean).
* `fqdn` - The fully qualified domain name (FQDN).

## Notes

* For workgroup computers, `domain` will contain the workgroup name, and `workgroup` will have the same value.
* For domain computers, `workgroup` will be empty.
* The `fqdn` attribute provides a convenient way to get the fully qualified name regardless of domain membership.
