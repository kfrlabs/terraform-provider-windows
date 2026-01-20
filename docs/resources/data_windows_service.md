# windows_service (Data Source)

Retrieves information about a Windows service.

## Example Usage

### Basic Service Query

```hcl
data "windows_service" "iis" {
  name = "W3SVC"
}

output "iis_status" {
  value = data.windows_service.iis.status
}

output "iis_startup" {
  value = data.windows_service.iis.start_type
}
```

### Query Multiple Services

```hcl
data "windows_service" "sql_server" {
  name = "MSSQLSERVER"
}

output "sql_info" {
  value = {
    display_name = data.windows_service.sql_server.display_name
    status       = data.windows_service.sql_server.status
    start_type   = data.windows_service.sql_server.start_type
    start_name   = data.windows_service.sql_server.start_name
  }
}
```

### Conditional Resource Based on Service

```hcl
data "windows_service" "iis" {
  name = "W3SVC"
}

resource "windows_registry_value" "iis_config" {
  count = data.windows_service.iis.status == "Running" ? 1 : 0
  
  path  = "HKLM:\\Software\\MyApp"
  name  = "IISAvailable"
  value = "true"
  type  = "String"
}
```

### Check Service Capabilities

```hcl
data "windows_service" "custom_service" {
  name = "MyCustomService"
}

output "service_capabilities" {
  value = {
    can_stop              = data.windows_service.custom_service.can_stop
    can_pause_and_continue = data.windows_service.custom_service.can_pause_and_continue
    can_shutdown          = data.windows_service.custom_service.can_shutdown
  }
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the Windows service to retrieve (not the display name).
* `command_timeout` - (Optional) Timeout in seconds for PowerShell commands. Defaults to `300`.

## Attribute Reference

In addition to all arguments above, the following attributes are exported:

* `id` - The service name.
* `display_name` - The display name of the service.
* `description` - A description of what the service does.
* `status` - The current status of the service. Possible values:
  * `Running` - Service is running
  * `Stopped` - Service is stopped
  * `Paused` - Service is paused
  * `StartPending` - Service is starting
  * `StopPending` - Service is stopping
  * `ContinuePending` - Service is resuming from pause
  * `PausePending` - Service is pausing
* `start_type` - The startup type of the service. Possible values:
  * `Automatic` - Starts automatically at boot
  * `Manual` - Starts manually
  * `Disabled` - Cannot be started
  * `Boot` - Device driver started by the boot loader
  * `System` - Device driver started by the kernel
* `start_name` - The account under which the service runs (e.g., `LocalSystem`, `NT AUTHORITY\NetworkService`, `DOMAIN\User`).
* `binary_path` - The path to the service executable.
* `service_type` - The type of service.
* `can_pause_and_continue` - Whether the service can be paused and continued (boolean).
* `can_shutdown` - Whether the service can be shut down (boolean).
* `can_stop` - Whether the service can be stopped (boolean).

## Common Services

Here are some commonly queried Windows services:

### Web Services
* `W3SVC` - IIS World Wide Web Publishing Service
* `WAS` - Windows Process Activation Service

### Database Services
* `MSSQLSERVER` - SQL Server (default instance)
* `MSSQL$INSTANCENAME` - SQL Server (named instance)

### System Services
* `Spooler` - Print Spooler
* `Dnscache` - DNS Client
* `Dhcp` - DHCP Client
* `WinRM` - Windows Remote Management

## Error Handling

If the specified service does not exist, the data source will return an error.
