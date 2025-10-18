# Windows Feature Resource

Manages Windows features on a Windows server via SSH and PowerShell remote execution.

## Table of Contents

1. [Example Usage](#example-usage)
2. [Argument Reference](#argument-reference)
3. [Attributes Reference](#attributes-reference)
4. [Common Features](#common-features)
5. [Advanced Examples](#advanced-examples)
6. [Import](#import)
7. [Troubleshooting](#troubleshooting)

---

## Example Usage

### Basic Usage

```hcl
resource "windows_feature" "web_server" {
  feature = "Web-Server"
  restart = true
}
```

### With Sub-features and Management Tools

```hcl
resource "windows_feature" "iis_full" {
  feature                  = "Web-Server"
  restart                  = true
  include_all_sub_features = true
  include_management_tools = true
  command_timeout          = 300
}
```

### Disabling a Feature

To remove a feature, use Terraform's `destroy` or modify the resource. The provider will handle the removal:

```hcl
resource "windows_feature" "telnet" {
  feature = "Telnet-Client"
  # Feature will be removed when destroyed
}
```

---

## Argument Reference

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| **feature** | string | The name of the Windows feature to install or remove. Examples: `Web-Server`, `RSAT-AD-Tools`, `Container`. |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| **restart** | bool | false | Whether to automatically restart the server if required after feature installation. When set to `true`, the server will reboot if necessary without manual intervention. |
| **include_all_sub_features** | bool | false | Whether to include all sub-features associated with the specified feature. When `true`, dependent features will also be installed. |
| **include_management_tools** | bool | false | Whether to include management tools for the specified feature. Useful for installing GUI management tools alongside the feature. |
| **command_timeout** | number | 300 | Timeout in seconds for PowerShell commands executed on the remote server. Increase this value for features with long installation times. |

---

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | The feature name (same as `feature` argument). Used as the unique identifier for the resource. |
| **state** | string | The current installation state of the feature. Possible values: `Installed`, `Available`, `Removed`. |
| **display_name** | string | The display name of the feature as shown in Windows Server Manager. |
| **description** | string | Description of the feature retrieved from the Windows server. |

---

## Common Features

### Web Server Features

| Feature Name | Description |
|--------------|-------------|
| `Web-Server` | Internet Information Services (IIS) core |
| `Web-WebServer` | IIS Web Server core component |
| `Web-Common-Http` | Common HTTP features (static content, directory browsing, etc.) |
| `Web-Default-Doc` | Default document support |
| `Web-Dir-Browsing` | Directory browsing |
| `Web-Http-Errors` | HTTP error pages |
| `Web-Static-Content` | Static content serving |
| `Web-Http-Redirect` | HTTP redirection |
| `Web-Health` | Health and diagnostics |
| `Web-Http-Logging` | HTTP logging |
| `Web-Custom-Logging` | Custom logging |
| `Web-Log-Libraries` | Logging libraries |
| `Web-ODBC-Logging` | ODBC logging |
| `Web-Request-Monitor` | Request monitoring |
| `Web-Http-Tracing` | HTTP tracing |
| `Web-Performance` | Performance features |
| `Web-Stat-Compression` | Static content compression |
| `Web-Dyn-Compression` | Dynamic content compression |
| `Web-Security` | Security features |
| `Web-Filtering` | Request filtering |
| `Web-Basic-Auth` | Basic authentication |
| `Web-CertProvider` | Certificate authentication mapping |
| `Web-Client-Auth` | Client certificate authentication |
| `Web-Digest-Auth` | Digest authentication |
| `Web-Cert-Auth` | IIS certificate authentication |
| `Web-Asp-Net` | ASP.NET support |
| `Web-Asp-Net45` | ASP.NET 4.5+ support |
| `Web-Net-Ext` | .NET Extensibility |
| `Web-AppInit` | Application Initialization |
| `Web-Mgmt-Tools` | Management tools and console |
| `Web-Mgmt-Console` | IIS Manager |
| `Web-Scripting-Tools` | IIS scripting tools |

### Active Directory and RSAT Features

| Feature Name | Description |
|--------------|-------------|
| `RSAT-AD-Tools` | Active Directory administration tools |
| `RSAT-AD-PowerShell` | Active Directory PowerShell module |
| `RSAT-AD-AdminCenter` | Active Directory Administrative Center |
| `RSAT-ADDS` | Active Directory Domain Services tools |
| `RSAT-DNS-Server` | DNS Server management tools |
| `RSAT-DHCP` | DHCP Server management tools |
| `RSAT-NPS` | Network Policy Server management tools |

### Container and Virtualization Features

| Feature Name | Description |
|--------------|-------------|
| `Container` | Container support and runtime |
| `Hyper-V` | Hyper-V virtualization platform |
| `Hyper-V-PowerShell` | Hyper-V PowerShell module |
| `Containers` | Container runtime (Windows/Docker) |

### Miscellaneous Features

| Feature Name | Description |
|--------------|-------------|
| `Telnet-Client` | Telnet client tool |
| `TFTP-Client` | TFTP (Trivial File Transfer Protocol) client |
| `NET-Framework-45-Core` | .NET Framework 4.5 core components |
| `NET-Framework-45-Features` | .NET Framework 4.5 features |
| `PowerShell-V2` | PowerShell 2.0 compatibility (legacy) |

---

## Advanced Examples

### Installing IIS with All Features

```hcl
resource "windows_feature" "iis_complete" {
  feature                  = "Web-Server"
  restart                  = true
  include_all_sub_features = true
  include_management_tools = true
  command_timeout          = 600
}
```

### Installing ASP.NET 4.5 Support

```hcl
resource "windows_feature" "aspnet45" {
  feature                  = "Web-Asp-Net45"
  restart                  = false
  include_all_sub_features = true
}

resource "windows_feature" "dotnet45" {
  feature = "NET-Framework-45-Features"
  restart = false
}
```

### Installing Multiple Related Features

```hcl
resource "windows_feature" "ad_tools" {
  feature = "RSAT-AD-Tools"
  restart = false
}

resource "windows_feature" "ad_powershell" {
  feature = "RSAT-AD-PowerShell"
  restart = false
}

resource "windows_feature" "ad_admin_center" {
  feature = "RSAT-AD-AdminCenter"
  restart = false
}
```

### Conditional Feature Installation Based on Variables

```hcl
variable "install_iis" {
  type    = bool
  default = false
}

resource "windows_feature" "iis" {
  count   = var.install_iis ? 1 : 0
  feature = "Web-Server"
  restart = true
}
```

### Installing Features with Custom Timeout

```hcl
resource "windows_feature" "hyper_v" {
  feature         = "Hyper-V"
  restart         = true
  command_timeout = 900  # 15 minutes for complex installation
}
```

---

## Import

Windows features can be imported using the feature name. This allows you to bring existing Windows features under Terraform management.

### Import Syntax

```shell
terraform import windows_feature.<resource_name> <feature_name>
```

### Import Examples

Import the Web-Server feature:

```shell
terraform import windows_feature.web_server Web-Server
```

Import Active Directory tools:

```shell
terraform import windows_feature.ad_tools RSAT-AD-Tools
```

### Import Multiple Features

Create a Terraform configuration with the resources you want to import:

```hcl
resource "windows_feature" "web_server" {}
resource "windows_feature" "rsat_ad" {}
```

Then import them:

```shell
terraform import windows_feature.web_server Web-Server
terraform import windows_feature.rsat_ad RSAT-AD-Tools
```

---

## Troubleshooting

### Feature Installation Fails

**Issue**: `installation failed` or `feature not found`

**Solutions**:
- Verify the feature name: `Get-WindowsFeature | Where-Object { $_.Name -like "*web*" }`
- Check if the feature exists on your Windows version
- Ensure the SSH user has administrator privileges
- Review PowerShell logs: `Get-EventLog -LogName System -Source "ServerManager" -Newest 10`

### Command Timeout

**Issue**: `command timed out`

**Solutions**:
- Increase `command_timeout` to a higher value (e.g., 600 or 900 seconds)
- Large features or slow servers may require longer timeouts
- Check server resource usage (CPU, memory, disk I/O)

### Reboot Required But Not Executed

**Issue**: Feature installed but `restart = false` and server hasn't rebooted

**Solutions**:
- Set `restart = true` if the feature requires a reboot
- Check Terraform logs for restart requirements
- Manually reboot with: `Restart-Computer -Force`

### Permission Denied

**Issue**: `access denied` during feature installation

**Solutions**:
- Verify the SSH user is in the Administrators group
- Check with: `whoami /groups | find "S-1-5-32-544"`
- Elevate to administrator if needed

### Feature Already Exists

**Issue**: Trying to import a feature that's already managed by Terraform

**Solutions**:
- Check if the resource already exists in your state: `terraform state list`
- If importing, use a different resource name
- Use `terraform state rm` to remove conflicting resources before importing

### SSH Connection Lost During Installation

**Issue**: Long-running feature installations timeout due to SSH inactivity

**Solutions**:
- Increase `command_timeout` to allow for longer operations
- Ensure the SSH connection has keep-alive enabled
- Split large feature installations across multiple resources
- Check network stability

### SubFeatures Not Installing

**Issue**: `include_all_sub_features = true` but sub-features not installed

**Solutions**:
- Verify the feature supports sub-features with: `Get-WindowsFeature Web-Server`
- Some features may have dependencies that need to be installed separately
- Check Windows version compatibility
- Review PowerShell installation logs

### Feature Removal Fails

**Issue**: Cannot remove a feature that another feature depends on

**Solutions**:
- First remove dependent features
- Use: `Get-WindowsFeature | Where-Object { $_.DependsOn -like "*FeatureName*" }`
- Remove dependencies before the main feature
- Manual removal with: `Remove-WindowsFeature -Name "FeatureName"`

---

## Notes

### Performance Considerations

- Large feature installations may take significant time. Increase `command_timeout` accordingly.
- Setting `restart = true` will cause the server to reboot, which may interrupt other operations.
- Plan feature installations during maintenance windows.

### Idempotency

- This resource is idempotent. Running `terraform apply` multiple times with the same configuration will not reinstall already-installed features.
- The provider checks the current state before making changes.

### State Management

- Always run `terraform plan` before `terraform apply` to review changes.
- Features are tied to the server they're installed on. Changing servers requires reimporting or recreating resources.
- Use `terraform state` commands carefully when managing imported resources.

### Compatibility

- Requires PowerShell 5.0 or later on the Windows server.
- Works with Windows Server 2019, 2022, and Windows 10/11 Pro/Enterprise.
- Some features may not be available on all Windows versions.