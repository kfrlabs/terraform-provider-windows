terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host     = var.windows_host
  username = var.windows_username
  password = var.windows_password
}

# Minimal example: a machine-scope environment variable through the built-in
# Environment DSC resource. The gateway converges with Test/Set/Test and
# removes the variable on destroy via destroy_properties (Ensure = "Absent").
resource "windows_dsc_resource" "example" {
  module_name   = "PSDesiredStateConfiguration"
  resource_name = "Environment"

  properties = {
    Ensure = "Present"
    Name   = "FOO"
    Value  = "bar"
    Target = ["Machine"]
  }

  destroy_properties = {
    Ensure = "Absent"
    Name   = "FOO"
  }
}

# Pinned module version: the exact version is used, otherwise the highest
# installed version is used and reported in resolved_module_version.
resource "windows_dsc_resource" "pinned" {
  module_name    = "PSDesiredStateConfiguration"
  module_version = "1.1"
  resource_name  = "Environment"

  properties = {
    Ensure = "Present"
    Name   = "FOO_PINNED"
    Value  = "bar"
    Target = ["Machine"]
  }

  destroy_properties = {
    Ensure = "Absent"
    Name   = "FOO_PINNED"
  }

  timeouts = {
    create = "30m"
    read   = "10m"
    update = "30m"
    delete = "30m"
  }
}

# PSCredential property: the map key is the DSC property name (here the
# optional Credential of the built-in Script resource). The password travels
# on stdin and never reaches state; bump credential_properties_wo_version to
# rotate. Note: WriteOnly values are unavailable at destroy time, so destroy
# configurations of credential-bearing resources must not require the
# credential.
resource "windows_dsc_resource" "script" {
  module_name   = "PSDesiredStateConfiguration"
  resource_name = "Script"

  properties = {
    GetScript  = "@{ Result = (Get-Content C:\\Windows\\Temp\\tf-dsc-marker.txt) }"
    SetScript  = "Set-Content C:\\Windows\\Temp\\tf-dsc-marker.txt 'managed'"
    TestScript = "Test-Path C:\\Windows\\Temp\\tf-dsc-marker.txt"
  }

  credential_properties_wo = {
    Credential = {
      username = var.script_run_username
      password = var.script_run_password
    }
  }
  credential_properties_wo_version = 1
}
