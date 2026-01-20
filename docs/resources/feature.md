# windows_feature

Manages Windows features (roles and role services) installation and removal.

## Example Usage

### Basic Feature Installation

```hcl
resource "windows_feature" "iis" {
  feature = "Web-Server"
}
```

### Feature with All Sub-Features

```hcl
resource "windows_feature" "iis_full" {
  feature                   = "Web-Server"
  include_all_sub_features = true
  include_management_tools = true
}
```

### Feature with Automatic Restart

```hcl
resource "windows_feature" "ad_tools" {
  feature = "RSAT-AD-Tools"
  restart = true
}
```

### Adopt Existing Feature

```hcl
resource "windows_feature" "existing_iis" {
  feature        = "Web-Server"
  allow_existing = true
}
```

### Feature with Custom Timeout

```hcl
resource "windows_feature" "dotnet" {
  feature         = "NET-Framework-45-Core"
  command_timeout = 600
}
```

## Argument Reference

The following arguments are supported:

* `feature` - (Required, Forces new resource) The name of the Windows feature to install (e.g., `Web-Server`, `RSAT-AD-Tools`).
* `restart` - (Optional) Whether to restart the server automatically if needed after installation. Defaults to `false`.
* `include_all_sub_features` - (Optional) Whether to include all sub-features of the specified feature. Defaults to `false`. Computed from actual installation state.
* `include_management_tools` - (Optional) Whether to include management tools for the specified feature. Defaults to `false`. Computed from actual installation state.
* `allow_existing` - (Optional) If `true`, adopt existing feature instead of failing. If `false`, fail if feature is already installed. Defaults to `false`.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300` (5 minutes).

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the feature.
* `install_state` - Current installation state of the Windows feature (e.g., `Installed`, `Available`, `Removed`).

## Import

Windows features can be imported using the feature name:

```shell
terraform import windows_feature.iis "Web-Server"
```

**Note:** Only installed features can be imported. The feature must already be installed on the system.

## Behavior Notes

### Existing Feature Handling

When creating a feature resource:
- If the feature is **not installed**, it will be installed normally.
- If the feature is **already installed**:
  - With `allow_existing = false` (default): Resource creation fails with a clear error message suggesting import or setting `allow_existing = true`.
  - With `allow_existing = true`: The existing feature is adopted into Terraform state without modification.

### Restart Behavior

- If `restart = true`, the server will restart automatically after installation if required.
- If `restart = false` (default) and a restart is needed, a warning is logged but no automatic restart occurs. A manual restart will be required for the feature to become fully functional.

### State Detection

The resource automatically detects the actual state of the feature during Read operations, including:
- Whether all sub-features are installed
- Whether management tools are installed
- Current installation state

## Common Features

### Web Server (IIS)
* `Web-Server` - IIS Web Server
* `Web-Asp-Net45` - ASP.NET 4.5
* `Web-Mgmt-Console` - IIS Management Console
* `Web-WebSockets` - WebSocket Protocol

### Remote Server Administration Tools (RSAT)
* `RSAT-AD-Tools` - Active Directory Tools
* `RSAT-DNS-Server` - DNS Server Tools
* `RSAT-DHCP` - DHCP Server Tools
* `RSAT-File-Services` - File Services Tools

### .NET Framework
* `NET-Framework-45-Core` - .NET Framework 4.5 Core
* `NET-Framework-45-ASPNET` - ASP.NET 4.5

### Other Common Features
* `Telnet-Client` - Telnet Client
* `SNMP-Service` - SNMP Service
* `Windows-Defender` - Windows Defender
* `Containers` - Containers feature