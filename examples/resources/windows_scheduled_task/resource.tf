terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host      = var.windows_host
  username  = var.windows_username
  password  = var.windows_password
  auth_type = "ntlm"
}

# Minimal example: daily task running as SYSTEM in the root folder.
resource "windows_scheduled_task" "backup" {
  name        = "Daily-Backup"
  path        = "\\"
  description = "Nightly backup script managed by Terraform."
  enabled     = true

  actions {
    execute   = "C:\\Scripts\\backup.ps1"
    arguments = "-Destination D:\\Backups"
  }

  triggers {
    type           = "Daily"
    start_boundary = "2026-01-01T02:00:00Z"
    days_interval  = 1
  }
}

# Advanced example: weekly task in a sub-folder, domain account, multiple actions.
resource "windows_scheduled_task" "reports" {
  name        = "Weekly-Reports"
  path        = "\\Company\\Finance\\"
  description = "Weekly report generation — Terraform-managed."
  enabled     = true

  principal {
    user_id             = "CORP\\svc-reports"
    logon_type          = "Password"
    password            = var.svc_reports_password
    password_wo_version = 1
    run_level           = "Highest"
  }

  actions {
    execute   = "C:\\Reports\\generate.exe"
    arguments = "--weekly --output C:\\Reports\\out"
  }

  actions {
    execute   = "C:\\Scripts\\archive.ps1"
    arguments = "-Source C:\\Reports\\out -Dest \\\\\\\\nas\\\\reports"
  }

  triggers {
    type           = "Weekly"
    start_boundary = "2026-01-05T06:00:00Z"
    days_of_week   = ["Monday"]
    weeks_interval = 1
  }

  settings {
    start_when_available           = true
    execution_time_limit           = "PT4H"
    disallow_start_if_on_batteries = false
    stop_if_going_on_batteries     = false
    multiple_instances             = "IgnoreNew"
  }
}

# OnEvent example: react to a Windows Event Log event.
resource "windows_scheduled_task" "disk_alert" {
  name    = "Disk-Full-Alert"
  path    = "\\Monitoring\\"
  enabled = true

  actions {
    execute   = "powershell.exe"
    arguments = "-File C:\\Scripts\\notify.ps1"
  }

  triggers {
    type         = "OnEvent"
    subscription = <<-XML
      <QueryList>
        <Query Id="0" Path="System">
          <Select Path="System">*[System[EventID=2013]]</Select>
        </Query>
      </QueryList>
    XML
  }
}
