# windows_service

Manages Windows services (start, stop, configure startup type).

## Example Usage

### Start a Service

```hcl
resource "windows_service" "iis" {
  name  = "W3SVC"
  state = "Running"
}
```

### Stop a Service

```hcl
resource "windows_service" "telnet" {
  name  = "TlntSvr"
  state = "Stopped"
}
```

### Configure Service Startup Type

```hcl
resource "windows_service" "windows_update" {
  name         = "wuauserv"
  startup_type = "Manual"
}
```

### Complete Service Configuration

```hcl
resource "windows_service" "my_app_service" {
  name         = "MyAppService"
  state        = "Running"
  startup_type = "Automatic"
}
```

### Service with Dependencies

```hcl
# Ensure IIS is installed
resource "windows_feature" "iis" {
  feature = "Web-Server"
}

# Configure and start IIS service
resource "windows_service" "iis" {
  name         = "W3SVC"
  state        = "Running"
  startup_type = "Automatic"
  
  depends_on = [windows_feature.iis]
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required, String, ForceNew) The name of the Windows service (service name, not display name). Examples: `"W3SVC"`, `"MSSQLSERVER"`, `"Spooler"`.

* `state` - (Optional, String) The desired state of the service. Valid values:
  - `"Running"` - Service should be running
  - `"Stopped"` - Service should be stopped
  - `"Paused"` - Service should be paused (if supported)
  
  If not specified, only the startup type will be configured.

* `startup_type` - (Optional, String) The startup type for the service. Valid values:
  - `"Automatic"` - Start automatically at boot
  - `"Manual"` - Start manually or when required
  - `"Disabled"` - Cannot be started
  - `"AutomaticDelayedStart"` - Start automatically with delay
  
  If not specified, the startup type will not be changed.

* `command_timeout` - (Optional, Number) Timeout in seconds for PowerShell commands. Default: `300` (5 minutes).

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The service name.

* `display_name` - The display name of the service (read-only).

* `status` - Current status of the service (read-only). Examples: `"Running"`, `"Stopped"`, `"StartPending"`.

## Import

Windows services can be imported using the service name:

```bash
terraform import windows_service.iis W3SVC
```

## Service Names vs Display Names

### Service Name (Use This)

The internal service name used in Windows. This is what you must use in the `name` argument.

Examples:
- `W3SVC` (IIS)
- `MSSQLSERVER` (SQL Server)
- `WinRM` (Windows Remote Management)
- `Spooler` (Print Spooler)

### Display Name (For Reference)

The human-readable name shown in Services management console.

Examples:
- World Wide Web Publishing Service (W3SVC)
- SQL Server (MSSQLSERVER)
- Windows Remote Management (WinRM)
- Print Spooler (Spooler)

### Finding Service Names

To find the service name for a service:

```powershell
# List all services with name and display name
Get-Service | Select-Object Name, DisplayName, Status | Format-Table -AutoSize

# Search by display name
Get-Service | Where-Object {$_.DisplayName -like "*IIS*"}

# Get specific service details
Get-Service -Name "W3SVC" | Select-Object *
```

From command line:
```cmd
sc query
sc query state= all
```

## Service States

### Running

Service is currently running.

```hcl
resource "windows_service" "example" {
  name  = "MyService"
  state = "Running"
}
```

When you set `state = "Running"`:
- If stopped, Terraform will start the service
- If paused, Terraform will resume the service
- If already running, no action taken

### Stopped

Service is not running.

```hcl
resource "windows_service" "example" {
  name  = "TelnetService"
  state = "Stopped"
}
```

When you set `state = "Stopped"`:
- If running or paused, Terraform will stop the service
- If already stopped, no action taken

### Paused

Service is paused (not all services support this state).

```hcl
resource "windows_service" "example" {
  name  = "MyService"
  state = "Paused"
}
```

**Note**: Not all services support pause/resume. Services that don't support pause will return an error.

## Startup Types

### Automatic

Service starts automatically when the system boots.

```hcl
resource "windows_service" "critical_service" {
  name         = "MyCriticalService"
  startup_type = "Automatic"
  state        = "Running"
}
```

**Use for**: Essential services that must run at all times.

### Automatic (Delayed Start)

Service starts automatically but after other automatic services have started.

```hcl
resource "windows_service" "background_service" {
  name         = "MyBackgroundService"
  startup_type = "AutomaticDelayedStart"
}
```

**Use for**: Non-critical services to speed up boot time.

### Manual

Service must be started manually or by another service.

```hcl
resource "windows_service" "on_demand_service" {
  name         = "MyOnDemandService"
  startup_type = "Manual"
}
```

**Use for**: Services that are used occasionally.

### Disabled

Service cannot be started.

```hcl
resource "windows_service" "unused_service" {
  name         = "UnusedService"
  startup_type = "Disabled"
}
```

**Use for**: Services you want to permanently disable.

## Common Windows Services

### IIS (Web Server)

```hcl
resource "windows_service" "iis" {
  name         = "W3SVC"
  state        = "Running"
  startup_type = "Automatic"
}

resource "windows_service" "iis_admin" {
  name         = "IISADMIN"
  state        = "Running"
  startup_type = "Automatic"
}
```

### SQL Server

```hcl
resource "windows_service" "sql_server" {
  name         = "MSSQLSERVER"  # Default instance
  state        = "Running"
  startup_type = "Automatic"
}

resource "windows_service" "sql_agent" {
  name         = "SQLSERVERAGENT"
  state        = "Running"
  startup_type = "Automatic"
}

# Named instance: use "MSSQL$INSTANCENAME"
resource "windows_service" "sql_instance" {
  name         = "MSSQL$MYINSTANCE"
  state        = "Running"
  startup_type = "Automatic"
}
```

### Remote Desktop

```hcl
resource "windows_service" "rdp" {
  name         = "TermService"
  state        = "Running"
  startup_type = "Automatic"
}
```

### Windows Update

```hcl
resource "windows_service" "windows_update" {
  name         = "wuauserv"
  startup_type = "Manual"  # Often set to Manual to control updates
}
```

### Print Spooler

```hcl
resource "windows_service" "print_spooler" {
  name         = "Spooler"
  state        = "Running"
  startup_type = "Automatic"
}
```

### Windows Firewall

```hcl
resource "windows_service" "firewall" {
  name         = "MpsSvc"
  state        = "Running"
  startup_type = "Automatic"
}
```

### DNS Client

```hcl
resource "windows_service" "dns_client" {
  name         = "Dnscache"
  state        = "Running"
  startup_type = "Automatic"
}
```

### Task Scheduler

```hcl
resource "windows_service" "task_scheduler" {
  name         = "Schedule"
  state        = "Running"
  startup_type = "Automatic"
}
```

### Windows Time

```hcl
resource "windows_service" "windows_time" {
  name         = "W32Time"
  state        = "Running"
  startup_type = "Automatic"
}
```

### WinRM (Windows Remote Management)

```hcl
resource "windows_service" "winrm" {
  name         = "WinRM"
  state        = "Running"
  startup_type = "Automatic"
}
```

## Managing Custom Services

### Application Service

```hcl
resource "windows_service" "my_app" {
  name         = "MyApplication"
  state        = "Running"
  startup_type = "Automatic"
}
```

### Multiple Application Services

```hcl
locals {
  app_services = {
    "MyAppAPI"     = { state = "Running", startup = "Automatic" }
    "MyAppWorker"  = { state = "Running", startup = "Automatic" }
    "MyAppMonitor" = { state = "Running", startup = "AutomaticDelayedStart" }
  }
}

resource "windows_service" "app_services" {
  for_each = local.app_services
  
  name         = each.key
  state        = each.value.state
  startup_type = each.value.startup
}
```

## Service Lifecycle Management

### Starting a Stopped Service

```hcl
# Before: service is stopped
resource "windows_service" "app" {
  name  = "MyAppService"
  state = "Stopped"
}

# After: service will be started
resource "windows_service" "app" {
  name  = "MyAppService"
  state = "Running"
}
```

### Changing Startup Type Without Affecting State

```hcl
resource "windows_service" "app" {
  name         = "MyAppService"
  startup_type = "Manual"
  # No 'state' specified - current state is preserved
}
```

### Restart Behavior

To restart a service (stop then start):

```hcl
# This provider doesn't directly support restart
# But you can:
# 1. Set state to "Stopped"
# 2. Apply
# 3. Set state to "Running"
# 4. Apply again

# Or use provisioners (not recommended)
resource "null_resource" "restart_service" {
  triggers = {
    version = var.app_version
  }
  
  provisioner "local-exec" {
    command = "ssh admin@server 'Restart-Service -Name MyAppService'"
  }
}
```

## Dependencies and Ordering

### Service Depends on Feature

```hcl
resource "windows_feature" "iis" {
  feature = "Web-Server"
}

resource "windows_service" "iis" {
  name         = "W3SVC"
  state        = "Running"
  startup_type = "Automatic"
  
  depends_on = [windows_feature.iis]
}
```

### Start Services in Order

```hcl
resource "windows_service" "database" {
  name  = "MSSQLSERVER"
  state = "Running"
}

resource "windows_service" "app" {
  name  = "MyAppService"
  state = "Running"
  
  depends_on = [windows_service.database]
}
```

### Service Depends on Configuration

```hcl
# Create registry configuration
resource "windows_registry_value" "app_config" {
  path  = "HKLM:\\Software\\MyApp"
  name  = "DatabaseServer"
  type  = "String"
  value = "sql-server.example.com"
}

# Start service after configuration
resource "windows_service" "app" {
  name  = "MyAppService"
  state = "Running"
  
  depends_on = [windows_registry_value.app_config]
}
```

## Error Handling

### Service Doesn't Exist

If the service doesn't exist, Terraform will error. Ensure:
- Service is installed
- Service name is correct (use `Get-Service` to verify)

### Cannot Start Service

Common reasons:
- Service is disabled (`startup_type = "Disabled"`)
- Dependencies are not running
- Service binary is missing or corrupt
- Permission issues

### Cannot Stop Service

Some services are protected and cannot be stopped. Examples:
- Critical system services
- Services with dependents that are running

## Security Considerations

### Service Account

This resource doesn't manage the service account. To change the service account:

```powershell
# Use PowerShell or sc.exe
sc.exe config MyService obj= "NT AUTHORITY\NetworkService" password= ""

# Or PowerShell
$credential = Get-Credential
Set-Service -Name MyService -Credential $credential
```

### Permissions

The SSH user needs:
- **Read** permission to query service status
- **Start/Stop** permission to change service state
- **Configure** permission to change startup type

For most services, administrator privileges are required.

### Critical Services

Be careful with critical system services:

⚠️ **Don't stop these** (system may become unstable):
- `RpcSs` (Remote Procedure Call)
- `DcomLaunch` (DCOM Server Process Launcher)
- `PlugPlay` (Plug and Play)
- `CryptSvc` (Cryptographic Services)
- `EventLog` (Windows Event Log)

## Troubleshooting

### Permission Denied

**Issue**: Access denied when managing service

**Solution**:
- SSH user must have administrator rights
- Check service permissions: `sc.exe sdshow MyService`

### Service Not Found

**Issue**: Service name not found

**Solution**:
- List all services: `Get-Service | Format-Table -AutoSize`
- Use service name, not display name
- Check if service is installed

### Service Dependency Error

**Issue**: Cannot start service due to dependency

**Solution**:
- Check dependencies: `sc.exe qc MyService`
- Ensure dependent services are running
- Use `depends_on` in Terraform

### Timeout Starting Service

**Issue**: Service takes too long to start

**Solution**:
- Increase `command_timeout`
- Check service logs for startup issues
- Verify service configuration

### Service Won't Stop

**Issue**: Service cannot be stopped

**Solution**:
- Check if other services depend on it: `sc.exe enumdepend MyService`
- Stop dependent services first
- Check if service is marked as "cannot stop"

## Best Practices

### State vs Startup Type

Configure both for production services:

```hcl
resource "windows_service" "production_app" {
  name         = "MyAppService"
  state        = "Running"        # Current state
  startup_type = "Automatic"      # Boot behavior
}
```

### Conditional Service Management

```hcl
variable "enable_telnet" {
  type    = bool
  default = false
}

resource "windows_service" "telnet" {
  count = var.enable_telnet ? 1 : 0
  
  name         = "TlntSvr"
  state        = "Running"
  startup_type = "Manual"
}
```

### Health Checks

After starting services, verify they're healthy:

```hcl
resource "null_resource" "health_check" {
  depends_on = [windows_service.app]
  
  provisioner "local-exec" {
    command = "curl -f http://localhost:8080/health || exit 1"
  }
}
```

### Documentation

```hcl
resource "windows_service" "app" {
  name         = "MyAppService"
  state        = "Running"
  startup_type = "Automatic"
  
  # Service purpose: Main application API service
  # Required for: Customer-facing API
  # Dependencies: MSSQLSERVER
  # Owner: Platform Team
}
```

## Notes

- Service name is case-insensitive in Windows
- Not all services support pause/resume
- Some services require elevated privileges to manage
- Service state changes may take a few seconds
- Terraform tracks desired state, not runtime state
- Service may be started by other processes between Terraform runs

## Related Resources

- `windows_feature` - Install Windows features that include services
- Some features automatically install and configure services
- Use registry resources to configure service parameters
- Consider Windows service account management separately
