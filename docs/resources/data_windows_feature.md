# windows_feature (Data Source)

Retrieves information about a Windows feature installed on the system.

## Example Usage

### Basic Feature Query

```hcl
data "windows_feature" "iis" {
  name = "Web-Server"
}

output "iis_installed" {
  value = data.windows_feature.iis.installed
}
```

### Check Feature with Details

```hcl
data "windows_feature" "rsat_ad" {
  name = "RSAT-AD-Tools"
}

output "feature_info" {
  value = {
    display_name  = data.windows_feature.rsat_ad.display_name
    installed     = data.windows_feature.rsat_ad.installed
    install_state = data.windows_feature.rsat_ad.install_state
    feature_type  = data.windows_feature.rsat_ad.feature_type
  }
}
```

### Conditional Resource Based on Feature

```hcl
data "windows_feature" "iis" {
  name = "Web-Server"
}

resource "windows_service" "iis_service" {
  count = data.windows_feature.iis.installed ? 1 : 0
  
  name  = "W3SVC"
  state = "Running"
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the Windows feature to retrieve (e.g., `Web-Server`, `RSAT-AD-Tools`).
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300`.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the feature.
* `display_name` - The display name of the feature.
* `description` - A description of the feature.
* `installed` - Whether the feature is currently installed (boolean).
* `install_state` - The installation state of the feature (e.g., `Installed`, `Available`, `Removed`).
* `feature_type` - The type of feature (e.g., `Role`, `Role Service`, `Feature`).
* `path` - The path of the feature in the feature tree.
* `sub_features` - Comma-separated list of sub-features.

## Common Feature Names

Here are some commonly used Windows feature names:

### Web Server (IIS)
* `Web-Server` - IIS Web Server
* `Web-Asp-Net45` - ASP.NET 4.5
* `Web-Mgmt-Console` - IIS Management Console

### Remote Server Administration Tools (RSAT)
* `RSAT-AD-Tools` - Active Directory Tools
* `RSAT-DNS-Server` - DNS Server Tools
* `RSAT-DHCP` - DHCP Server Tools

### Other Features
* `Telnet-Client` - Telnet Client
* `SNMP-Service` - SNMP Service
* `NET-Framework-45-Core` - .NET Framework 4.5 Core
