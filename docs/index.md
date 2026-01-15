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
- Go >= 1.18
- A Windows server with OpenSSH Server installed
- SSH access to the Windows server

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

---

## Resources

The provider supports the following resources:

- [windows_feature](resources/windows_feature.md) - Manage Windows features
- [windows_hostname](resources/windows_hostname.md) - Manage Windows hostname
- [windows_localuser](resources/windows_localuser.md) - Manage local users
- [windows_localgroup](resources/windows_localgroup.md) - Manage local groups
- [windows_registry_key](resources/windows_registry_key.md) - Manage registry keys
- [windows_registry_value](resources/windows_registry_value.md) - Manage registry values
- [windows_service](resources/windows_service.md) - Manage Windows services

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
- Verify permissions of the `authorized_keys` file

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

### Connection Timeout

**Issue**: `connection timeout`

**Solutions**:
- Increase `conn_timeout` (e.g., 60 seconds)
- Check network connectivity: `ping 192.168.1.1`
- Verify port 22 is open: `Test-NetConnection -ComputerName 192.168.1.1 -Port 22`

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

❌ **DON'T**:
- Never use `skip_host_key_verification = true` in production
- Never commit credentials in plain text
- Don't share private keys
- Don't use weak passwords

### Credential Management

**Use sensitive variables**:

```hcl
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

### SSH Keys

**Generate a secure key**:

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
```

**Protect the private key**:

```bash
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh
```

### Terraform State

**Protect the state**:
- Use an encrypted backend (S3, Azure Storage, Terraform Cloud)
- Enable versioning and encryption
- Never commit `terraform.tfstate` in plain text

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

---

## Version Compatibility

| Provider Version | Terraform Version | Go Version |
|-----------------|-------------------|------------|
| 0.0.7           | >= 1.0            | >= 1.18    |

---

## Support

For issues, questions, or feature requests, please open an issue on [GitHub Issues](https://github.com/kfrlabs/terraform-provider-windows/issues).
