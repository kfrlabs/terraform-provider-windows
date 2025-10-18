# Terraform Provider for Windows

## Table of Contents

1. [Installation](#installation)
2. [Provider Configuration](#provider-configuration)
3. [Connecting to Windows Servers](#connecting-to-windows-servers)
4. [Resources](#resources)
5. [Troubleshooting](#troubleshooting)
6. [Security](#security)

---

## Installation

### Prerequisites
- Terraform >= 1.0
- A Windows server with OpenSSH Server installed
- SSH access to the Windows server

### Installing the Provider

Add the provider to your Terraform configuration:

```hcl
terraform {
  required_providers {
    windows = {
      source  = "your-org/windows"
      version = "~> 1.0"
    }
  }
}
```

---

## Provider Configuration

### Basic Configuration

```hcl
provider "windows" {
  host            = "192.168.1.1"
  username        = "admin"
  password        = "password"
  conn_timeout    = 30
}
```

### Configuration with Private Key

```hcl
provider "windows" {
  host            = "192.168.1.1"
  username        = "admin"
  key_path        = "~/.ssh/id_rsa"
  conn_timeout    = 30
}
```

### Configuration with SSH Agent

```hcl
provider "windows" {
  host            = "192.168.1.1"
  username        = "admin"
  use_ssh_agent   = true
  conn_timeout    = 30
}
```

### Environment Variables (Recommended)

To avoid storing credentials in plain text:

```hcl
provider "windows" {
  host            = var.windows_host
  username        = var.windows_username
  password        = sensitive(var.windows_password)
  conn_timeout    = 30
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

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| **host** | string | Yes | Hostname or IP address of the Windows server |
| **username** | string | Yes | Username for SSH authentication |
| **password** | string | No | SSH password (required if `use_ssh_agent` is false and `key_path` is not defined) |
| **key_path** | string | No | Path to the private SSH key (PEM format) |
| **use_ssh_agent** | bool | No | Use SSH agent for authentication (default: false) |
| **conn_timeout** | number | No | SSH connection timeout in seconds (default: 30) |

---

## Connecting to Windows Servers

This provider connects to Windows servers via SSH and executes PowerShell commands remotely. Here's how to set up your infrastructure.

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

# Set appropriate permissions (read-only private key)
icacls $env:USERPROFILE\.ssh /inheritance:r
icacls $env:USERPROFILE\.ssh /grant "$($env:USERNAME):(R,W)"
icacls $env:USERPROFILE\.ssh\authorized_keys /inheritance:r
icacls $env:USERPROFILE\.ssh\authorized_keys /grant "$($env:USERNAME):(R)"

# Set permissions for SYSTEM (if needed)
icacls $env:USERPROFILE\.ssh /grant "NT AUTHORITY\SYSTEM:(R,W)"
icacls $env:USERPROFILE\.ssh\authorized_keys /grant "NT AUTHORITY\SYSTEM:(R)"
```

#### 4. Copying Public Key via SCP (from the client)

If you have temporary SSH access from a Linux/macOS machine:

```bash
scp ~/.ssh/id_rsa.pub admin@192.168.1.1:C:/Users/Admin/.ssh/authorized_keys
```

### Provider Support

- ✅ Password authentication
- ✅ Private key authentication (PEM file)
- ✅ SSH Agent
- ✅ Configurable connection timeout

---

## Resources

### windows_hostname

Manages the hostname of a Windows server.

#### Usage Example

```hcl
resource "windows_hostname" "example" {
  hostname = "MY-NEW-SERVER"
}
```

#### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| **hostname** | string | Yes | New hostname (max 15 characters) |

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | Unique identifier (hostname) |
| **hostname** | string | Current hostname |
| **requires_reboot** | bool | Indicates if a reboot is required |

---

### windows_feature

Manages Windows feature activation or deactivation.

#### Usage Example

```hcl
# Enable IIS
resource "windows_feature" "iis" {
  name    = "Web-Server"
  enabled = true
}

# Enable IIS with Management Tools
resource "windows_feature" "iis_mgmt" {
  name    = "Web-Mgmt-Tools"
  enabled = true
}

# Disable a feature
resource "windows_feature" "telnet" {
  name    = "Telnet-Client"
  enabled = false
}
```

#### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| **name** | string | Yes | Windows feature name (e.g., "Web-Server", "RSAT-AD-Tools") |
| **enabled** | bool | Yes | Enable (true) or disable (false) the feature |
| **restart_required** | bool | No | Restart if necessary (default: false) |

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | Unique identifier (feature name) |
| **installed** | bool | Current installation state |

#### Common Features

- `Web-Server` - IIS
- `Web-Mgmt-Tools` - IIS Management Tools
- `RSAT-AD-Tools` - Active Directory Tools
- `Telnet-Client` - Telnet Client
- `Container` - Container Support

---

### windows_registry_key

Manages Windows registry keys.

#### Usage Example

```hcl
resource "windows_registry_key" "example" {
  path   = "HKLM:\\Software\\MyApp"
  action = "create"
}

resource "windows_registry_key" "delete_old_key" {
  path   = "HKLM:\\Software\\OldApp"
  action = "delete"
}
```

#### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| **path** | string | Yes | Full registry key path (e.g., "HKLM:\\Software\\MyApp") |
| **action** | string | Yes | "create" or "delete" |

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | Registry key path |
| **exists** | bool | Indicates whether the key exists |

#### Supported Hives

- `HKCR` - Root Classes
- `HKCU` - Current User
- `HKLM` - Local Machine
- `HKU` - Users
- `HKCC` - Current Hardware Configuration

---

### windows_registry_value

Manages Windows registry values.

#### Usage Example

```hcl
# Create a string value
resource "windows_registry_value" "app_name" {
  key   = "HKLM:\\Software\\MyApp"
  name  = "AppName"
  type  = "string"
  value = "My Application"
}

# Create a DWORD value
resource "windows_registry_value" "max_connections" {
  key   = "HKLM:\\Software\\MyApp"
  name  = "MaxConnections"
  type  = "dword"
  value = "100"
}

# Create a multi-string value
resource "windows_registry_value" "paths" {
  key   = "HKLM:\\Software\\MyApp"
  name  = "SearchPaths"
  type  = "multistring"
  value = "C:\\Path1;C:\\Path2"
}
```

#### Arguments

| Argument | Type | Required | Description |
|----------|------|----------|-------------|
| **key** | string | Yes | Path to the parent key (e.g., "HKLM:\\Software\\MyApp") |
| **name** | string | Yes | Registry value name |
| **type** | string | Yes | Type: "string", "dword", "binary", "multistring", "qword" |
| **value** | string | Yes | Value to set |

#### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | Unique identifier (key\name) |
| **previous_value** | string | Previous value (if one existed) |

#### Supported Types

- `string` - Standard text value
- `dword` - 32-bit integer
- `qword` - 64-bit integer
- `binary` - Binary data
- `multistring` - Multiple strings separated by semicolons

---

## Troubleshooting

### SSH Connection Errors

**Issue**: `connection refused`

**Solutions**:
- Verify that the SSH service is running: `Get-Service sshd`
- Check firewall rules: `Get-NetFirewallRule -Name sshd`
- Test manually: `ssh admin@192.168.1.1`

**Issue**: `authentication failed`

**Solutions**:
- Verify your credentials
- For key-based authentication, check that `authorized_keys` contains the correct public key
- Verify permissions of the `authorized_keys` file (read-only for the user)

### Permission Errors

**Issue**: `access denied` when managing features or registry

**Solutions**:
- The SSH user must have administrator rights
- For features, run: `whoami /groups | find "S-1-5-32-544"` (verify Administrators membership)
- For the registry, check permissions: `regedit` → Edit → Permissions

### Private Key Errors

**Issue**: `invalid private key format` or `permission denied`

**Solutions**:
- Verify PEM format: `-----BEGIN RSA PRIVATE KEY-----`
- Check file permissions: `chmod 600 ~/.ssh/id_rsa`
- Regenerate the key if needed: `ssh-keygen -t rsa -b 4096`

### Connection Timeout

**Issue**: `connection timeout`

**Solutions**:
- Increase `conn_timeout` (e.g., 60 seconds)
- Check network connectivity: `ping 192.168.1.1`
- Verify port 22 is open: `Test-NetConnection -ComputerName 192.168.1.1 -Port 22`

### Server Reboot

**Issue**: Need to reboot the server after making changes

**Solutions**:
- Use `restart_required = true` in feature resources
- Manual reboot: `Restart-Computer -Force`
- Schedule a reboot: `Restart-Computer -AsJob -Delay 60`

---

## Security

### ⚠️ Important Warnings

**Host Key Verification**

The provider currently uses an insecure host key callback that accepts any host key. This exposes your infrastructure to man-in-the-middle attacks. For production, it is **strongly recommended** to:

1. Implement host key fingerprint verification
2. Maintain a list of known host keys
3. Use a VPN or private network for connections

**Migration to Secure Callback** (example for contributors):

```go
// Example code to implement verification
hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
    // Implement verification against known_hosts
    return knownHosts.Check(hostname, remote, key)
}
```

### Credential Management

**Do not do**:
```hcl
# ❌ Do not commit credentials in plain text
provider "windows" {
  username = "admin"
  password = "MyPassword123"
}
```

**Do this**:
```hcl
# ✅ Use sensitive variables
provider "windows" {
  username = var.windows_username
  password = sensitive(var.windows_password)
}
```

**Set via environment variables**:
```bash
export TF_VAR_windows_username="admin"
export TF_VAR_windows_password="MyPassword123"
terraform plan
```

**Use Terraform Cloud/Enterprise**:
- Store sensitive variables in secure backend
- Encryption at rest and in transit
- Automatic audit logging

### SSH Keys

**Generate a secure key**:
```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N "passphrase"
```

**Protect the private key**:
```bash
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh
```

**Rotate regularly**:
- Generate a new key pair every 6-12 months
- Update `authorized_keys` on servers
- Remove old keys

### Access Control

**Principle of least privilege**:
- The SSH user only needs to be an administrator if required by resources
- For registry read-only access, use a non-admin user if possible
- Regularly audit permissions

**Example of limited permissions**:
```powershell
# Create a specialized user with limited rights
New-LocalUser -Name "terraform-user" -Password (ConvertTo-SecureString "Password123!" -AsPlainText -Force)

# Add to administrators (if needed)
Add-LocalGroupMember -Group "Administrators" -Member "terraform-user"
```

### Terraform State

**Protect the state**:
- Do not commit `terraform.tfstate` in plain text
- Use an encrypted backend (S3, Azure Storage, Terraform Cloud)
- Enable versioning and encryption

**Example with S3**:
```hcl
terraform {
  backend "s3" {
    bucket         = "terraform-state"
    key            = "windows/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"
  }
}
```

### Audit and Monitoring

- Enable SSH authentication logging on the Windows server
- Monitor access to critical registry keys
- Use a SIEM to detect suspicious activities
- Retain logs for at least 90 days