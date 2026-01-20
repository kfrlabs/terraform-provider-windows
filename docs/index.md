# Terraform Provider for Windows

Terraform provider for managing Windows servers via SSH and PowerShell. Configure Windows features, services, users, groups, registry, and more using Infrastructure as Code.

## Table of Contents

1. [Installation](#installation)
2. [Provider Configuration](#provider-configuration)
3. [Connecting to Windows Servers](#connecting-to-windows-servers)
4. [Resources](#resources)
5. [Data Sources](#data-sources)
6. [Common Features](#common-features)
7. [Troubleshooting](#troubleshooting)
8. [Security](#security)
9. [Examples](#examples)

---

## Installation

### Prerequisites

- Terraform >= 1.0
- Go >= 1.18 (for building from source)
- Windows Server 2016+ or Windows 10+ with OpenSSH Server
- SSH access to the Windows server
- Administrator privileges on the target Windows system

### Installing the Provider

Add the provider to your Terraform configuration:

```hcl
terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.0.7"
    }
  }
}
```

Then run:

```bash
terraform init
```

---

## Provider Configuration

### Basic Configuration

```hcl
provider "windows" {
  host         = "192.168.1.1"
  username     = "admin"
  password     = "password"
  conn_timeout = 30
}
```

### Configuration with Private Key

```hcl
provider "windows" {
  host         = "192.168.1.1"
  username     = "admin"
  key_path     = "~/.ssh/id_rsa"
  conn_timeout = 30
}
```

### Configuration with SSH Agent

```hcl
provider "windows" {
  host          = "192.168.1.1"
  username      = "admin"
  use_ssh_agent = true
  conn_timeout  = 30
}
```

### Configuration with Host Key Verification (Recommended)

```hcl
provider "windows" {
  host                       = "192.168.1.1"
  username                   = "admin"
  password                   = var.windows_password
  known_hosts_path           = "~/.ssh/known_hosts"
  strict_host_key_checking   = true
  conn_timeout               = 30
}
```

### Configuration with Host Key Fingerprints

```hcl
provider "windows" {
  host                       = "192.168.1.1"
  username                   = "admin"
  password                   = var.windows_password
  host_key_fingerprints      = ["SHA256:xxxxxx..."]
  strict_host_key_checking   = true
  conn_timeout               = 30
}
```

### Environment Variables (Recommended)

To avoid storing credentials in plain text:

```hcl
provider "windows" {
  host         = var.windows_host
  username     = var.windows_username
  password     = sensitive(var.windows_password)
  conn_timeout = 30
}
```

```hcl
# variables.tf
variable "windows_host" {
  type        = string
  description = "IP address or hostname of the Windows server"
}

variable "windows_username" {
  type        = string
  description = "SSH username"
}

variable "windows_password" {
  type        = string
  sensitive   = true
  description = "SSH password"
}
```

### Argument Reference

| Argument | Type | Required | Default | Description |
|----------|------|----------|---------|-------------|
| **host** | string | Yes | - | Hostname or IP address of the Windows server |
| **username** | string | Yes | - | Username for SSH authentication |
| **password** | string | No | - | SSH password (required if `use_ssh_agent` is false and `key_path` is not defined) |
| **key_path** | string | No | - | Path to the private SSH key (PEM format) |
| **use_ssh_agent** | bool | No | false | Use SSH agent for authentication |
| **conn_timeout** | number | No | 30 | SSH connection timeout in seconds |
| **known_hosts_path** | string | No | ~/.ssh/known_hosts | Path to the SSH known_hosts file for host key verification |
| **host_key_fingerprints** | list(string) | No | [] | List of expected SSH host key fingerprints (SHA256 format) |
| **strict_host_key_checking** | bool | No | false | If true, fail if host key is not found or doesn't match |
| **skip_host_key_verification** | bool | No | false | ⚠️ **DEPRECATED & INSECURE**: Skip SSH host key verification entirely |

---

## Connecting to Windows Servers

This provider connects to Windows servers via SSH and executes PowerShell commands remotely.

### Server Prerequisites (Windows)

#### 1. Installing and Enabling OpenSSH Server

On the Windows server (Windows 10 / Server 2019+), run as administrator:

```powershell
# Install OpenSSH Server (if not already installed)
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start the service
Start-Service sshd

# Enable at startup
Set-Service -Name sshd -StartupType 'Automatic'

# Check status
Get-Service sshd

# Open port 22 in the firewall
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH SSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

#### 2. Configuring Password Authentication

No additional configuration required. The user simply needs valid credentials on the Windows server.

#### 3. Configuring Key-based Authentication

Run on the Windows server (as the target user):

```powershell
# Create the .ssh directory
mkdir $env:USERPROFILE\.ssh -Force

# Add the public key to authorized_keys
Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value "<PASTE_YOUR_PUBLIC_KEY_HERE>" -NoNewline

# Set appropriate permissions
icacls $env:USERPROFILE\.ssh /inheritance:r
icacls $env:USERPROFILE\.ssh /grant "$($env:USERNAME):(R,W)"
icacls $env:USERPROFILE\.ssh\authorized_keys /inheritance:r
icacls $env:USERPROFILE\.ssh\authorized_keys /grant "$($env:USERNAME):(R)"
icacls $env:USERPROFILE\.ssh /grant "NT AUTHORITY\SYSTEM:(R,W)"
icacls $env:USERPROFILE\.ssh\authorized_keys /grant "NT AUTHORITY\SYSTEM:(R)"
```

### Provider Features

- ✅ Password authentication
- ✅ Private key authentication (PEM file)
- ✅ SSH Agent support
- ✅ Configurable connection timeout
- ✅ Host key verification (known_hosts or fingerprints)
- ✅ Secure command execution with input validation
- ✅ Comprehensive error messages
- ✅ Import support for existing resources

---

## Resources

The provider supports the following resources for managing Windows infrastructure:

### System Configuration

| Resource | Description | Documentation |
|----------|-------------|---------------|
| [windows_feature](resources/windows_feature.md) | Install and manage Windows features and roles | [View Docs](resources/windows_feature.md) |
| [windows_hostname](resources/windows_hostname.md) | Configure Windows hostname | [View Docs](resources/windows_hostname.md) |
| [windows_service](resources/windows_service.md) | Create and manage Windows services | [View Docs](resources/windows_service.md) |

### User and Group Management

| Resource | Description | Documentation |
|----------|-------------|---------------|
| [windows_localuser](resources/windows_localuser.md) | Manage local user accounts | [View Docs](resources/windows_localuser.md) |
| [windows_localgroup](resources/windows_localgroup.md) | Manage local groups | [View Docs](resources/windows_localgroup.md) |
| [windows_localgroupmember](resources/windows_localgroupmember.md) | Manage local group membership | [View Docs](resources/windows_localgroupmember.md) |

### Registry Management

| Resource | Description | Documentation |
|----------|-------------|---------------|
| [windows_registry_key](resources/windows_registry_key.md) | Create and manage registry keys | [View Docs](resources/windows_registry_key.md) |
| [windows_registry_value](resources/windows_registry_value.md) | Set and manage registry values | [View Docs](resources/windows_registry_value.md) |

---

## Data Sources

The provider supports the following data sources for querying Windows infrastructure:

### System Information

| Data Source | Description | Documentation |
|-------------|-------------|---------------|
| [windows_feature](data-sources/windows_feature.md) | Query Windows feature information | [View Docs](data-sources/windows_feature.md) |
| [windows_hostname](data-sources/windows_hostname.md) | Query hostname and domain information | [View Docs](data-sources/windows_hostname.md) |
| [windows_service](data-sources/windows_service.md) | Query Windows service information | [View Docs](data-sources/windows_service.md) |

### User and Group Information

| Data Source | Description | Documentation |
|-------------|-------------|---------------|
| [windows_localuser](data-sources/windows_localuser.md) | Query local user account information | [View Docs](data-sources/windows_localuser.md) |
| [windows_localgroup](data-sources/windows_localgroup.md) | Query local group information | [View Docs](data-sources/windows_localgroup.md) |
| [windows_localgroupmembers](data-sources/windows_localgroupmembers.md) | List members of a local group | [View Docs](data-sources/windows_localgroupmembers.md) |

### Registry Information

| Data Source | Description | Documentation |
|-------------|-------------|---------------|
| [windows_registry_value](data-sources/windows_registry_value.md) | Read registry values | [View Docs](data-sources/windows_registry_value.md) |

---

## Common Features

All resources and data sources share common features for better management and reliability.

### Adopt Existing Resources

Use `allow_existing = true` to manage existing Windows resources without recreating them:

```hcl
resource "windows_feature" "iis" {
  feature        = "Web-Server"
  allow_existing = true  # Adopt if already installed
}

resource "windows_localuser" "admin" {
  username       = "Administrator"
  password       = var.admin_password
  allow_existing = true  # Manage existing user
}
```

**Benefits:**
- Import existing infrastructure into Terraform
- Avoid "already exists" errors
- Gradually migrate to Infrastructure as Code
- Update configurations of existing resources

### Custom Timeouts

Configure timeout for long-running operations:

```hcl
resource "windows_feature" "large_feature" {
  feature         = "Web-Server"
  command_timeout = 600  # 10 minutes
}

resource "windows_service" "slow_service" {
  name            = "SlowService"
  command_timeout = 300  # 5 minutes (default)
}
```

### Import Support

All resources support importing existing Windows resources:

```bash
# Import existing feature
terraform import windows_feature.iis "Web-Server"

# Import existing user
terraform import windows_localuser.admin "Administrator"

# Import existing service
terraform import windows_service.iis "W3SVC"

# Import registry key
terraform import windows_registry_key.app "HKLM:\\Software\\MyApp"

# Import registry value
terraform import windows_registry_value.setting "HKLM:\\Software\\MyApp\\Setting"

# Import group membership
terraform import windows_localgroupmember.admin "Administrators/AppUser"
```

### Error Handling

The provider provides detailed, actionable error messages:

```
Error: Feature already exists
  Feature is already installed (InstallState: Installed).
  To manage this existing feature, either:
    1. Import it: terraform import windows_feature.iis Web-Server
    2. Set allow_existing = true in your configuration
    3. Remove it first: Remove-WindowsFeature -Name 'Web-Server'
```

### Security Features

- **Input Validation:** All parameters are validated for PowerShell injection attacks
- **Sensitive Data:** Passwords and credentials are marked as sensitive
- **Secure Connections:** SSH with host key verification
- **Audit Trail:** All operations are logged

---

## Troubleshooting

### SSH Connection Errors

**Issue**: `connection refused`

**Solutions**:
- Verify that the SSH service is running: `Get-Service sshd`
- Check firewall rules: `Get-NetFirewallRule -Name sshd`
- Test manually: `ssh admin@192.168.1.1`
- Verify port 22 is listening: `netstat -ano | findstr :22`

**Issue**: `authentication failed`

**Solutions**:
- Verify your credentials
- For key-based authentication, check that `authorized_keys` contains the correct public key
- Verify permissions of the `authorized_keys` file
- Check SSH logs: `Get-WinEvent -LogName "OpenSSH/Operational" -MaxEvents 20`

**Issue**: `host key verification failed`

**Solutions**:
- Add the host key to your `known_hosts` file
- Or provide the host key fingerprint in `host_key_fingerprints`
- Get the host key fingerprint: `ssh-keyscan -t rsa 192.168.1.1 | ssh-keygen -lf -`

### Permission Errors

**Issue**: `access denied` when managing features or registry

**Solutions**:
- The SSH user must have administrator rights
- Verify membership: `whoami /groups | find "S-1-5-32-544"`
- Check registry permissions in `regedit`
- Ensure UAC is not blocking administrative operations

**Issue**: `service account permissions`

**Solutions**:
- Grant "Log on as a service" right to service accounts
- Use `secpol.msc` → Local Policies → User Rights Assignment → Log on as a service
- Or use PowerShell: `Grant-UserRight -Account ".\ServiceAccount" -Right SeServiceLogonRight`

### Connection Timeout

**Issue**: `connection timeout`

**Solutions**:
- Increase `conn_timeout` in provider configuration (e.g., 60 seconds)
- Check network connectivity: `ping 192.168.1.1`
- Verify port 22 is open: `Test-NetConnection -ComputerName 192.168.1.1 -Port 22`
- Check for network issues or slow DNS resolution

### Resource Errors

**Issue**: `resource already exists`

**Solutions**:
- Set `allow_existing = true` to adopt the resource
- Or import the existing resource: `terraform import <resource_type>.<name> <id>`
- Or remove the resource manually and run `terraform apply` again

**Issue**: `pending reboot` (hostname changes)

**Solutions**:
- Set `restart = true` for automatic reboot
- Or manually restart the server: `Restart-Computer -Force`
- The resource will detect the change after reboot

### Debug Mode

Enable detailed logging for troubleshooting:

```bash
export TF_LOG=DEBUG
export TF_LOG_PATH=terraform-debug.log
terraform apply
```

---

## Security

### Security Best Practices

✅ **DO**:
- Use `known_hosts_path` or `host_key_fingerprints` for host key verification
- Set `strict_host_key_checking = true` in production
- Use environment variables or Terraform Cloud for credentials
- Rotate SSH keys regularly (every 6-12 months)
- Use private networks or VPN for connections
- Enable audit logging on Windows servers
- Use principle of least privilege for SSH users
- Store Terraform state in encrypted backends
- Use separate accounts for Terraform automation
- Review and audit changes before applying

❌ **DON'T**:
- Never use `skip_host_key_verification = true` in production
- Never commit credentials in plain text
- Don't share private keys
- Don't use weak passwords
- Don't use the same account for multiple purposes
- Don't disable Windows Firewall without good reason

### Credential Management

**Use sensitive variables**:

```hcl
provider "windows" {
  username = var.windows_username
  password = sensitive(var.windows_password)
}

variable "windows_password" {
  type      = string
  sensitive = true
}
```

**Set via environment variables**:

```bash
export TF_VAR_windows_username="admin"
export TF_VAR_windows_password="MyPassword123"
terraform plan
```

**Use Terraform Cloud / Enterprise**:

Store sensitive variables in Terraform Cloud workspaces with encryption at rest.

### SSH Keys

**Generate a secure key**:

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_windows -C "terraform-windows"
```

**Protect the private key**:

```bash
chmod 600 ~/.ssh/id_rsa_windows
chmod 700 ~/.ssh
```

**Use SSH Agent**:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_rsa_windows
```

```hcl
provider "windows" {
  host          = var.windows_host
  username      = var.windows_username
  use_ssh_agent = true
}
```

### Terraform State

**Protect the state**:
- Use an encrypted backend (S3, Azure Storage, Terraform Cloud)
- Enable versioning and encryption
- Never commit `terraform.tfstate` to version control
- Use state locking to prevent concurrent modifications
- Restrict access to state storage

**Example with S3**:

```hcl
terraform {
  backend "s3" {
    bucket         = "terraform-state"
    key            = "windows/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
    kms_key_id     = "arn:aws:kms:eu-west-1:123456789:key/xxxxx"
  }
}
```

**Example with Azure Storage**:

```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "terraform-state-rg"
    storage_account_name = "terraformstate"
    container_name       = "tfstate"
    key                  = "windows.terraform.tfstate"
  }
}
```

### Registry Security

When managing the Windows Registry:
- Only modify keys you own (avoid built-in Windows keys)
- Never store passwords or secrets in the registry
- Use appropriate registry hives (HKLM for system-wide, HKCU for user-specific)
- Test changes in non-production environments first
- Back up registry keys before making changes

---

## Examples

### Complete Web Server Setup

```hcl
# Install IIS
resource "windows_feature" "iis" {
  feature                   = "Web-Server"
  include_all_sub_features = true
  include_management_tools = true
}

# Ensure IIS service is running
resource "windows_service" "iis" {
  name           = "W3SVC"
  start_type     = "Automatic"
  state          = "Running"
  allow_existing = true
  
  depends_on = [windows_feature.iis]
}

# Create IIS application pool user
resource "windows_localuser" "iis_app_pool" {
  username                    = "IISAppPool"
  password                    = var.app_pool_password
  password_never_expires      = true
  user_cannot_change_password = true
}

# Add to IIS_IUSRS group
resource "windows_localgroupmember" "iis_membership" {
  group  = "IIS_IUSRS"
  member = windows_localuser.iis_app_pool.username
}

# Configure application in registry
resource "windows_registry_key" "app_config" {
  path = "HKLM:\\Software\\MyWebApp"
}

resource "windows_registry_value" "app_name" {
  path  = windows_registry_key.app_config.path
  name  = "ApplicationName"
  value = "My Web Application"
  type  = "String"
}
```

### Database Server Configuration

```hcl
# Create database service account
resource "windows_localuser" "sql_service" {
  username                    = "SQLServiceAccount"
  password                    = var.sql_password
  full_name                   = "SQL Server Service Account"
  password_never_expires      = true
  user_cannot_change_password = true
}

# Create DBA group
resource "windows_localgroup" "dbas" {
  name        = "DatabaseAdmins"
  description = "Database administrators"
}

# Add service account to local administrators
resource "windows_localgroupmember" "sql_admin" {
  group  = "Administrators"
  member = windows_localuser.sql_service.username
}

# Configure SQL Server service
resource "windows_service" "sql_server" {
  name           = "MSSQLSERVER"
  start_name     = ".\\${windows_localuser.sql_service.username}"
  credential     = var.sql_password
  start_type     = "Automatic"
  state          = "Running"
  allow_existing = true
}
```

### Multi-Environment Configuration

```hcl
variable "environment" {
  type = string
}

variable "config" {
  type = map(object({
    app_name    = string
    timeout     = number
    enable_debug = bool
  }))
  
  default = {
    dev = {
      app_name     = "MyApp-Dev"
      timeout      = 30
      enable_debug = true
    }
    prod = {
      app_name     = "MyApp"
      timeout      = 300
      enable_debug = false
    }
  }
}

# Environment-specific hostname
resource "windows_hostname" "server" {
  hostname = "${var.config[var.environment].app_name}-SERVER"
}

# Environment-specific registry configuration
resource "windows_registry_key" "env_config" {
  path  = "HKLM:\\Software\\MyApp\\${var.environment}"
  force = true
}

resource "windows_registry_value" "environment" {
  path  = windows_registry_key.env_config.path
  name  = "Environment"
  value = var.environment
  type  = "String"
}

resource "windows_registry_value" "timeout" {
  path  = windows_registry_key.env_config.path
  name  = "Timeout"
  value = tostring(var.config[var.environment].timeout)
  type  = "DWord"
}

resource "windows_registry_value" "debug" {
  path  = windows_registry_key.env_config.path
  name  = "EnableDebug"
  value = var.config[var.environment].enable_debug ? "1" : "0"
  type  = "DWord"
}
```

---

## Version Compatibility

| Provider Version | Terraform Version | Go Version | Windows Version |
|-----------------|-------------------|------------|-----------------|
| 0.0.7           | >= 1.0            | >= 1.18    | Server 2016+, Win 10+ |

### Tested On

- ✅ Windows Server 2019
- ✅ Windows Server 2022
- ✅ Windows 10 (1809+)
- ✅ Windows 11

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## Support

For issues, questions, or feature requests:

- 📝 [GitHub Issues](https://github.com/kfrlabs/terraform-provider-windows/issues)
- 📖 [Documentation](https://registry.terraform.io/providers/kfrlabs/windows/latest/docs)
- 💬 [Discussions](https://github.com/kfrlabs/terraform-provider-windows/discussions)

---

## License

This provider is released under the [Mozilla Public License 2.0](LICENSE).