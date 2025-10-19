# Windows Service Resource

Manages Windows services on a Windows server via SSH and PowerShell remote execution. This resource handles creation, modification, and deletion of Windows services with support for startup types, credentials, state management, and service dependencies.

## Table of Contents

1. [Example Usage](#example-usage)
2. [Argument Reference](#argument-reference)
3. [Attributes Reference](#attributes-reference)
4. [Startup Types](#startup-types)
5. [Service Accounts](#service-accounts)
6. [Advanced Examples](#advanced-examples)
7. [Import](#import)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

---

## Example Usage

### Basic Service

```hcl
resource "windows_service" "myapp" {
  name        = "MyAppService"
  binary_path = "C:\\Program Files\\MyApp\\service.exe"
  start_type  = "Automatic"
}
```

### Service with Credentials

```hcl
resource "windows_service" "myapp_service" {
  name        = "MyAppService"
  binary_path = "C:\\Program Files\\MyApp\\service.exe"
  start_type  = "Automatic"
  state       = "Running"
  
  start_name  = "NT AUTHORITY\\NetworkService"
  description = "MyApp Windows Service"
  display_name = "MyApp Service"
}
```

### Service with Custom Account

```hcl
resource "windows_localuser" "service_account" {
  username                    = "svc_myapp"
  password                    = var.service_account_password
  password_never_expires      = true
  user_cannot_change_password = true
}

resource "windows_service" "myapp_custom" {
  name        = "MyAppService"
  binary_path = "C:\\Program Files\\MyApp\\service.exe"
  start_type  = "Automatic"
  state       = "Running"
  
  start_name  = windows_localuser.service_account.username
  credential  = var.service_account_password
  description = "MyApp service running under custom account"
}
```

---

## Argument Reference

### Required Arguments

| Argument | Type | Description |
|----------|------|-------------|
| **name** | string | The name of the Windows service. Must be unique on the system. Maximum 256 characters. Cannot be changed after service creation (ForceNew). |
| **binary_path** | string | The full path to the service executable file (e.g., `C:\Program Files\MyApp\service.exe`). Required when creating a new service. Cannot be changed after creation (ForceNew). |

### Optional Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| **display_name** | string | empty | The display name shown in Windows Services application and Services MMC. User-friendly name for the service. Maximum 256 characters. |
| **description** | string | empty | A description of what the service does. Displayed in Services application. Maximum 1024 characters. |
| **start_type** | string | Manual | The startup type: `Automatic` (starts on boot), `Manual` (started manually), `Disabled` (cannot be started), `Boot` (driver service started at boot), or `System` (driver service started by system loader). |
| **state** | string | Stopped | The desired state of the service: `Running` (service is running) or `Stopped` (service is stopped). |
| **start_name** | string | empty | The account under which the service runs. Examples: `LocalSystem`, `NT AUTHORITY\NetworkService`, `NT AUTHORITY\LocalService`, or `DOMAIN\username`. |
| **credential** | string | empty | The password for the service account if `start_name` is a domain or local user account. Required when `start_name` is not a built-in account. Sensitive field. |
| **load_order_group** | string | empty | The load order group for driver services. Used to control the order in which drivers are loaded. |
| **service_type** | string | Win32OwnProcess | The type of service: `Win32OwnProcess`, `Win32ShareProcess`, `KernelDriver`, or `FileSystemDriver`. Usually read-only for user services. |
| **depend_on_service** | set(string) | [] | List of service names this service depends on. Service will not start until dependencies are running. |
| **command_timeout** | number | 300 | Timeout in seconds for PowerShell commands executed on the remote server. Increase for slow systems. |

---

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

| Attribute | Type | Description |
|-----------|------|-------------|
| **id** | string | The service name (same as `name` argument). Used as the unique identifier. |
| **status** | string | The current operational status: `Running` or `Stopped`. Read-only attribute. |
| **service_type** | string | The actual service type detected from the system. Read-only. |
| **start_name** | string | The account the service is configured to run as. Read-only. |

---

## Startup Types

Windows services support different startup types that control how and when the service starts:

| Startup Type | Description | Use Cases |
|--------------|-------------|-----------|
| **Automatic** | Service starts automatically at system boot | Production services, critical applications, monitoring agents |
| **Manual** | Service must be started manually or by another process | Optional utilities, maintenance tools, developer services |
| **Disabled** | Service cannot be started (must be enabled first) | Unused services, services being transitioned, security-restricted services |
| **Boot** | Driver starts at system boot (driver services only) | Critical system drivers, hardware drivers |
| **System** | Driver started by system loader (driver services only) | Core system drivers, kernel-mode drivers |

### Startup Type Examples

```hcl
# Production service - automatic startup
resource "windows_service" "production_app" {
  name        = "ProdApp"
  binary_path = "C:\\Apps\\ProdApp\\service.exe"
  start_type  = "Automatic"
  state       = "Running"
}

# Development/testing - manual startup
resource "windows_service" "dev_app" {
  name        = "DevApp"
  binary_path = "C:\\Apps\\DevApp\\service.exe"
  start_type  = "Manual"
  state       = "Stopped"
}

# Disabled service - not in use
resource "windows_service" "legacy_service" {
  name        = "LegacyService"
  binary_path = "C:\\Apps\\Legacy\\service.exe"
  start_type  = "Disabled"
}
```

---

## Service Accounts

Windows services can run under different accounts with different privilege levels:

### Built-in Service Accounts

| Account | Full Name | Privileges | Use Cases |
|---------|-----------|-----------|-----------|
| **LocalSystem** | NT AUTHORITY\SYSTEM | Highest (local admin) | Services needing full system access |
| **NetworkService** | NT AUTHORITY\NetworkService | Medium (network access) | Services accessing network resources |
| **LocalService** | NT AUTHORITY\LocalService | Low (local machine only) | Isolated services, minimal privileges |

### Account Examples

```hcl
# LocalSystem (highest privileges)
resource "windows_service" "high_priv" {
  name       = "HighPrivService"
  binary_path = "C:\\Apps\\service.exe"
  start_name = "LocalSystem"
}

# NetworkService (network access, medium privileges)
resource "windows_service" "network_service" {
  name       = "NetworkService"
  binary_path = "C:\\Apps\\service.exe"
  start_name = "NT AUTHORITY\\NetworkService"
}

# LocalService (lowest privileges, local only)
resource "windows_service" "local_service" {
  name       = "LocalService"
  binary_path = "C:\\Apps\\service.exe"
  start_name = "NT AUTHORITY\\LocalService"
}

# Custom domain account
resource "windows_service" "domain_account" {
  name        = "DomainService"
  binary_path = "C:\\Apps\\service.exe"
  start_name  = "DOMAIN\\service_account"
  credential  = var.domain_account_password
}

# Custom local account
resource "windows_service" "local_account" {
  name        = "LocalAccountService"
  binary_path = "C:\\Apps\\service.exe"
  start_name  = "ComputerName\\localuser"
  credential  = var.local_account_password
}
```

---

## Advanced Examples

### Service with Dependencies

```hcl
resource "windows_service" "base_service" {
  name        = "BaseService"
  binary_path = "C:\\Apps\\base\\service.exe"
  start_type  = "Automatic"
}

resource "windows_service" "dependent_service" {
  name               = "DependentService"
  binary_path        = "C:\\Apps\\app\\service.exe"
  start_type         = "Automatic"
  depend_on_service  = [windows_service.base_service.name]
}
```

### Service with Custom Service Account

```hcl
resource "windows_localuser" "svc_account" {
  username                    = "svc_myapp"
  password                    = random_password.svc_password.result
  full_name                   = "MyApp Service Account"
  description                 = "Service account for MyApp"
  password_never_expires      = true
  user_cannot_change_password = true
  groups                      = ["Users"]
}

resource "random_password" "svc_password" {
  length      = 20
  special     = true
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
}

resource "windows_service" "myapp" {
  name        = "MyAppService"
  display_name = "MyApp Service"
  binary_path = "C:\\Program Files\\MyApp\\MyService.exe"
  description = "Main application service for MyApp"
  start_type  = "Automatic"
  state       = "Running"
  
  start_name  = ".\\${windows_localuser.svc_account.username}"
  credential  = random_password.svc_password.result
}

output "service_account_password" {
  description = "Service account password"
  value       = random_password.svc_password.result
  sensitive   = true
}
```

### Multiple Services with Environment Variables

```hcl
variable "environment" {
  type    = string
  default = "production"
}

variable "app_services" {
  type = map(object({
    binary_path = string
    display_name = string
    start_type = string
  }))
  default = {
    "web" = {
      binary_path = "C:\\Apps\\Web\\service.exe"
      display_name = "Web Service"
      start_type = "Automatic"
    }
    "worker" = {
      binary_path = "C:\\Apps\\Worker\\service.exe"
      display_name = "Background Worker"
      start_type = "Automatic"
    }
    "scheduler" = {
      binary_path = "C:\\Apps\\Scheduler\\service.exe"
      display_name = "Task Scheduler"
      start_type = "Automatic"
    }
  }
}

resource "windows_service" "app_services" {
  for_each = var.app_services

  name         = "${var.environment}-${each.key}"
  display_name = "${each.value.display_name} (${var.environment})"
  binary_path  = each.value.binary_path
  start_type   = each.value.start_type
  state        = "Running"
  description  = "Service for ${var.environment} environment"
}
```

### Conditional Service Creation

```hcl
variable "enable_monitoring_service" {
  type    = bool
  default = false
}

resource "windows_service" "monitoring" {
  count       = var.enable_monitoring_service ? 1 : 0
  name        = "MonitoringService"
  binary_path = "C:\\Apps\\Monitoring\\service.exe"
  start_type  = "Automatic"
  state       = "Running"
}
```

### Service Restart Configuration

```hcl
# Service with automatic restart on failure
resource "windows_service" "resilient_service" {
  name        = "ResilientService"
  binary_path = "C:\\Apps\\service.exe"
  start_type  = "Automatic"
  state       = "Running"
  description = "Service with restart capability"
}

# Note: Additional restart policies must be configured via registry or separately
# This resource manages basic service properties
```

---

## Import

Windows services can be imported using the service name, allowing you to bring existing services under Terraform management.

### Import Syntax

```shell
terraform import windows_service.<resource_name> <service_name>
```

### Import Examples

Import a single service:

```shell
terraform import windows_service.example MyAppService
```

Import multiple services:

```shell
terraform import windows_service.web WebService
terraform import windows_service.worker WorkerService
terraform import windows_service.scheduler SchedulerService
```

Create the resource configuration:

```hcl
resource "windows_service" "example" {
  name        = "MyAppService"
  binary_path = "C:\\Program Files\\MyApp\\service.exe"
}
```

Then import the existing service:

```shell
terraform import windows_service.example MyAppService
```

---

## Troubleshooting

### Service Creation Fails

**Issue**: `failed to create service` or `service creation error`

**Solutions**:
- Verify the binary path exists and is accessible: `Test-Path "C:\Program Files\MyApp\service.exe"`
- Ensure SSH user has administrator privileges
- Check the service name is unique: `Get-Service | Where-Object { $_.Name -eq "ServiceName" }`
- Verify the executable is a valid Windows service: check event logs
- Run manual creation: `New-Service -Name "ServiceName" -BinaryPathName "C:\path\to\exe.exe"`

### Access Denied

**Issue**: `access denied` or `permission denied` error

**Solutions**:
- Verify SSH user is in the Administrators group
- Check with: `whoami /groups | find "S-1-5-32-544"`
- Service creation and deletion require administrative privileges
- Check Windows Event Logs: `Get-EventLog -LogName System -Newest 20`

### Service Already Exists

**Issue**: `service already exists` error

**Solutions**:
- If service exists, import it: `terraform import windows_service.example ServiceName`
- Check existing services: `Get-Service`
- To recreate: delete via PowerShell: `Remove-Service -Name "ServiceName" -Force`
- Then use Terraform destroy and apply

### Credential Issues

**Issue**: `failed to update service credential` or authentication error

**Solutions**:
- Verify the service account exists and password is correct
- For domain accounts, use format: `DOMAIN\username`
- For local accounts, use format: `.\ username` or just `username`
- Ensure credential contains the correct password
- Check account has "Log on as a service" right (local security policy)

### Service Fails to Start

**Issue**: `failed to start service` or service won't run

**Solutions**:
- Check service state: `Get-Service -Name "ServiceName" | Select-Object Status`
- Review event logs: `Get-EventLog -LogName System -Source ServiceControl -Newest 10`
- Verify the binary path is correct: `Test-Path "C:\path\to\exe.exe"`
- Check service account permissions (can it access the executable?)
- Try manual start: `Start-Service -Name "ServiceName"`
- Check for service dependencies that aren't running

### Service Fails to Stop

**Issue**: `failed to stop service` or timeout when stopping

**Solutions**:
- The service may be in use or have open handles
- Force stop may take time: increase `command_timeout`
- Use: `Stop-Service -Name "ServiceName" -Force`
- Check dependencies: other services may depend on this one
- Review what's keeping handles open: `Get-Process | Where-Object { $_.Handles -gt 0 }`

### Startup Type Not Applied

**Issue**: `start_type` remains unchanged after update

**Solutions**:
- Verify the startup type was actually changed: `Get-Service -Name "ServiceName" | Select-Object StartType`
- Ensure the service can transition to the new startup type
- Try manual change: `Set-Service -Name "ServiceName" -StartupType "Automatic"`
- Some system services may have restricted startup types

### Service Account Change Fails

**Issue**: `failed to update service credential` or account change error

**Solutions**:
- Verify the new account exists on the system
- Ensure the account has "Log on as a service" right
- Local security policy may restrict which accounts can run services
- Open Local Security Policy: `secpol.msc`
- Check: Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment > Log on as a service

### SSH Connection Issues

**Issue**: Connection timeout or SSH error

**Solutions**:
- Increase `command_timeout` to allow more time
- Check network connectivity to the server
- Verify SSH credentials and access
- Test manually: `ssh admin@server-ip`

### Service Not Responding

**Issue**: Service appears running but not responding to commands

**Solutions**:
- The service may be hung or in a bad state
- Try manual restart: `Restart-Service -Name "ServiceName" -Force`
- Check Windows Event Logs for errors: `Get-EventLog -LogName Application -Newest 20`
- Investigate what the service is doing: Process Monitor (procmon.exe)

### State Mismatch

**Issue**: Service