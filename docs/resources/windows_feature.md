# windows_feature

Manages the installation and configuration of Windows features via PowerShell.

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
  include_all_sub_features  = true
  include_management_tools  = true
}
```

### Feature with Automatic Restart

```hcl
resource "windows_feature" "ad_tools" {
  feature        = "RSAT-AD-Tools"
  restart        = true
  command_timeout = 600
}
```

### Multiple Features

```hcl
resource "windows_feature" "iis" {
  feature                  = "Web-Server"
  include_management_tools = true
}

resource "windows_feature" "asp_net" {
  feature = "Web-Asp-Net45"
  depends_on = [windows_feature.iis]
}

resource "windows_feature" "web_mgmt" {
  feature = "Web-Mgmt-Console"
  depends_on = [windows_feature.iis]
}
```

## Argument Reference

The following arguments are supported:

* `feature` - (Required, String, ForceNew) The name of the Windows feature to install or remove. This is the feature name as used in PowerShell (e.g., "Web-Server", "RSAT-AD-Tools").

* `restart` - (Optional, Boolean) Whether to automatically restart the server if needed after installing the feature. Default: `false`.

* `include_all_sub_features` - (Optional, Boolean, Computed) Whether to include all sub-features of the specified feature. Default: `false`.

* `include_management_tools` - (Optional, Boolean, Computed) Whether to include management tools for the specified feature. Default: `false`.

* `command_timeout` - (Optional, Number) Timeout in seconds for PowerShell commands. Default: `300` (5 minutes).

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The feature name.

* `install_state` - Current installation state of the Windows feature (e.g., "Installed", "Available", "InstallPending").

## Import

Windows features can be imported using the feature name:

```bash
terraform import windows_feature.iis Web-Server
```

## Common Windows Features

Here are some commonly used Windows features:

### Web Server (IIS)
- `Web-Server` - Core IIS web server
- `Web-Mgmt-Tools` - IIS management tools
- `Web-Mgmt-Console` - IIS management console
- `Web-Asp-Net45` - ASP.NET 4.5
- `Web-Net-Ext45` - .NET Extensibility 4.5

### Active Directory
- `AD-Domain-Services` - Active Directory Domain Services
- `RSAT-AD-Tools` - AD administration tools
- `RSAT-ADDS` - AD DS tools
- `RSAT-AD-PowerShell` - AD PowerShell module

### Remote Desktop Services
- `RDS-RD-Server` - Remote Desktop Session Host
- `RDS-Licensing` - RD Licensing
- `RDS-Gateway` - RD Gateway
- `RDS-Web-Access` - RD Web Access

### Hyper-V
- `Hyper-V` - Hyper-V role
- `Hyper-V-Tools` - Hyper-V management tools
- `Hyper-V-PowerShell` - Hyper-V PowerShell module

### File and Storage Services
- `FS-FileServer` - File Server
- `FS-DFS-Namespace` - DFS Namespaces
- `FS-DFS-Replication` - DFS Replication
- `FS-Resource-Manager` - File Server Resource Manager

### Other Common Features
- `Telnet-Client` - Telnet client
- `SNMP-Service` - SNMP service
- `Container` - Containers
- `Windows-Defender` - Windows Defender

## Notes

### Feature Names

To list all available features on your Windows server, use:

```powershell
Get-WindowsFeature | Select-Object Name, DisplayName, InstallState | Format-Table -AutoSize
```

Or to search for a specific feature:

```powershell
Get-WindowsFeature | Where-Object {$_.DisplayName -like "*IIS*"} | Select-Object Name, DisplayName
```

### Restart Behavior

Some features require a system restart to complete installation. Use the `restart` argument to automatically restart the server when needed. Be aware that:

- The SSH connection will be lost during restart
- Terraform will wait for the command to complete
- Consider using a higher `command_timeout` for features that require restart

### Sub-Features and Management Tools

When `include_all_sub_features` is `true`, Terraform will install the main feature along with all its sub-features. Similarly, `include_management_tools` will install the associated management tools.

During `terraform plan` and `terraform apply`, these values may show as "computed" until the actual state is read from the server.

### Dependencies

When installing features that depend on other features, use Terraform's `depends_on` to ensure proper installation order:

```hcl
resource "windows_feature" "iis" {
  feature = "Web-Server"
}

resource "windows_feature" "asp_net" {
  feature = "Web-Asp-Net45"
  depends_on = [windows_feature.iis]
}
```

## Security Considerations

- The SSH user must have administrator privileges to install Windows features
- Feature installation may require system restart
- Some features may open additional network ports
- Always review the security implications of features before installation

## Timeouts

The `command_timeout` argument controls how long Terraform will wait for the PowerShell command to complete. Increase this value for features that take longer to install:

```hcl
resource "windows_feature" "large_feature" {
  feature         = "AD-Domain-Services"
  command_timeout = 900  # 15 minutes
}
```
