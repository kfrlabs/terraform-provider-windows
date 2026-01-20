# windows_service

Manages Windows services (create, configure, start, stop).

## Example Usage

### Manage Existing Service State

```hcl
resource "windows_service" "iis" {
  name       = "W3SVC"
  state      = "Running"
  start_type = "Automatic"
  allow_existing = true
}
```

### Create New Service

```hcl
resource "windows_service" "my_app" {
  name         = "MyAppService"
  display_name = "My Application Service"
  description  = "Custom application service"
  binary_path  = "C:\\Program Files\\MyApp\\service.exe"
  start_type   = "Automatic"
  state        = "Running"
}
```

### Service with Custom Account

```hcl
resource "windows_localuser" "service_account" {
  username                    = "MyServiceAccount"
  password                    = var.service_password
  password_never_expires      = true
  user_cannot_change_password = true
}

resource "windows_service" "custom_service" {
  name        = "CustomService"
  binary_path = "C:\\Services\\custom.exe"
  start_name  = ".\\${windows_localuser.service_account.username}"
  credential  = var.service_password
  start_type  = "Automatic"
  state       = "Running"
}
```

### Service with Dependencies

```hcl
resource "windows_service" "dependent_service" {
  name               = "DependentService"
  binary_path        = "C:\\Services\\dependent.exe"
  start_type         = "Automatic"
  depend_on_service  = ["W3SVC", "MSSQLSERVER"]
  state              = "Running"
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required, Forces new resource) The name of the Windows service (e.g., `W3SVC`, `MyAppService`). This is the internal service name, not the display name. Cannot be changed after creation.
* `display_name` - (Optional, Computed) The display name of the service shown in the Services application. If not specified for a new service, it defaults to the service name.
* `description` - (Optional, Computed) A description of what the service does.
* `binary_path` - (Optional, Computed, Forces new resource) The full path to the service executable (e.g., `C:\\Program Files\\MyApp\\service.exe`). **Required when creating a new service**. Cannot be changed after creation.
* `start_type` - (Optional) The startup type of the service. Defaults to `Manual`. Valid values:
  - `Automatic` - Starts automatically at boot
  - `Manual` - Starts manually  
  - `Disabled` - Cannot be started
  - `Boot` - Device driver started by boot loader
  - `System` - Device driver started by kernel
* `state` - (Optional) The desired state of the service. Defaults to `Stopped`. Valid values:
  - `Running` - Service should be running
  - `Stopped` - Service should be stopped
* `start_name` - (Optional, Computed) The account under which the service runs. Common values:
  - `LocalSystem` - Local System account (default)
  - `NT AUTHORITY\\NetworkService` - Network Service account
  - `NT AUTHORITY\\LocalService` - Local Service account
  - `.\\username` - Local user account
  - `DOMAIN\\username` - Domain user account
* `credential` - (Optional, Sensitive) The password for the service account if `start_name` is a domain or local user account. Only used during creation and update. Not stored in state.
* `load_order_group` - (Optional) The load order group for driver services.
* `service_type` - (Optional, Computed) The type of service. Valid values:
  - `Win32OwnProcess` - Service runs in its own process (most common)
  - `Win32ShareProcess` - Service shares a process with other services
  - `KernelDriver` - Kernel device driver
  - `FileSystemDriver` - File system driver
* `depend_on_service` - (Optional) Set of service names this service depends on. The service will not start until all dependencies are running.
* `allow_existing` - (Optional) If `true`, adopt existing service instead of failing. If `false`, fail if service already exists. Defaults to `false`.
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300` (5 minutes).

## Attributes Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The name of the service.

## Import

Windows services can be imported using the service name:

```shell
terraform import windows_service.iis "W3SVC"
```

**Note:** When importing services that run under a user account, you must provide the `credential` in your configuration if you plan to manage the service account, as passwords cannot be retrieved.

## Behavior Notes

### Creating vs Managing Services

The resource behaves differently depending on whether the service already exists:

**New Service Creation:**
- `binary_path` is **required**
- Service will be created with all specified configuration
- Other attributes use defaults if not specified

**Managing Existing Service:**
- Set `allow_existing = true`
- `binary_path` is not required (will be read from existing service)
- Only specified attributes will be managed
- Service configuration will be updated to match

### Service States

The `state` attribute controls the running state:
- `Running`: Terraform will start the service if stopped
- `Stopped`: Terraform will stop the service if running

State changes are applied after configuration changes.

### Service Account Management

When using a custom service account:
1. Create the user account first
2. Ensure the account has "Log on as a service" rights
3. Provide the password via the `credential` attribute
4. For local accounts, use `.\\username` format in `start_name`
5. For domain accounts, use `DOMAIN\\username` format

The `credential` is only used when the service is created or when `start_name` is changed. It is not stored in Terraform state.

### Service Dependencies

Services listed in `depend_on_service` must exist on the system. The dependent service will not start until all dependencies are in a running state.

### Start Type vs State

These are independent settings:
- `start_type` determines when the service starts automatically (boot, on-demand, never)
- `state` determines if the service should be running right now

Common combinations:
- `start_type = "Automatic"` + `state = "Running"`: Service starts at boot and is running now
- `start_type = "Manual"` + `state = "Stopped"`: Service can be started manually but is stopped
- `start_type = "Disabled"` + `state = "Stopped"`: Service cannot be started

## Complete Examples

### IIS Web Server Management

```hcl
# Ensure IIS is installed
resource "windows_feature" "iis" {
  feature = "Web-Server"
}

# Manage W3SVC service
resource "windows_service" "iis" {
  name           = "W3SVC"
  start_type     = "Automatic"
  state          = "Running"
  allow_existing = true
  
  depends_on = [windows_feature.iis]
}
```

### Custom Application Service

```hcl
# Create service account
resource "windows_localuser" "app_service" {
  username                    = "AppService"
  password                    = var.service_password
  full_name                   = "Application Service Account"
  password_never_expires      = true
  user_cannot_change_password = true
}

# Grant service account necessary permissions
resource "windows_localgroupmember" "service_operators" {
  group  = "Performance Log Users"
  member = windows_localuser.app_service.username
}

# Create and configure service
resource "windows_service" "app" {
  name         = "MyApplication"
  display_name = "My Application Service"
  description  = "Provides application functionality"
  binary_path  = "C:\\Program Files\\MyApp\\service.exe"
  start_name   = ".\\${windows_localuser.app_service.username}"
  credential   = var.service_password
  start_type   = "Automatic"
  state        = "Running"
}
```

### Service with Multiple Dependencies

```hcl
resource "windows_service" "web_app" {
  name              = "WebApplication"
  display_name      = "Web Application Service"
  binary_path       = "C:\\WebApp\\service.exe"
  start_type        = "Automatic"
  depend_on_service = ["W3SVC", "MSSQLSERVER", "WinRM"]
  state             = "Running"
}
```

## Common Services

### Web Services
* `W3SVC` - IIS World Wide Web Publishing Service
* `WAS` - Windows Process Activation Service
* `IISADMIN` - IIS Admin Service

### Database Services
* `MSSQLSERVER` - SQL Server (default instance)
* `MSSQL$INSTANCENAME` - SQL Server (named instance)
* `SQLWriter` - SQL Server VSS Writer

### System Services
* `WinRM` - Windows Remote Management
* `Spooler` - Print Spooler
* `Dnscache` - DNS Client
* `Dhcp` - DHCP Client
* `EventLog` - Windows Event Log

## Troubleshooting

### Service Won't Start

Check:
1. Binary path is correct and executable exists
2. Service account has necessary permissions
3. Dependencies are running
4. Service account has "Log on as a service" right
5. Check Windows Event Logs for service-specific errors

### Permission Denied Errors

Ensure:
- Service account has access to binary path
- Service account has "Log on as a service" right
- Service account has access to any resources the service needs

### Terraform Times Out

Increase `command_timeout` if service operations take longer than 5 minutes:
```hcl
command_timeout = 600  # 10 minutes
```