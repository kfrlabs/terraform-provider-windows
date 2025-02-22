terraform {
  required_providers {
    tf-windows = {
      source = "local/k9fr4n/tf-windows"
    }
  }
}

provider "tf-windows" {
  host          = "172.18.190.4"
  username      = "adminlocalecritel"
  use_ssh_agent = true
}

resource "tf-windows_feature" "powershell" {
  features                 = ["PowerShellRoot", "Powershell"]
  restart                  = false
  include_all_sub_features = false
  include_management_tools = false
  command_timeout          = 300
}

### REGISTRY ###
resource "tf-windows_registry" "wsus_server" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  name  = "WUServer"
  type  = "String"
  value = "https://wsus.ecritel.net"
}

resource "tf-windows_registry" "wsus_status_server" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  name  = "WUStatusServer"
  type  = "String"
  value = "https://wsus.ecritel.net"
}
resource "tf-windows_registry" "target_group" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  name  = "TargetGroup"
  type  = "String"
  value = "OPTAVIS"
}

resource "tf-windows_registry" "target_group_enabled" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  name  = "TargetGroupEnabled"
  type  = "DWord"
  value = "1"
}

resource "tf-windows_registry" "test" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\TEST"
}

resource "tf-windows_registry" "use_wsus" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
  name  = "UseWUServer"
  type  = "DWord"
  value = "1"
}

# Configurer les mises à jour automatiques
resource "tf-windows_registry" "automatic_updates" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
  name  = "NoAutoUpdate"
  type  = "DWord"
  value = "1"
}

# Configurer l'option de mise à jour automatique
resource "tf-windows_registry" "automatic_update_option" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
  name  = "AUOptions"
  type  = "DWord"
  value = "3"
}