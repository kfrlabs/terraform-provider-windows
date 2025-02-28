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

resource "tf-windows_feature" "features" {
  for_each                = toset(["PowerShellRoot", "Powershell"])
  feature                 = each.key
  restart                 = false
  include_all_sub_features = false
  include_management_tools = false
  command_timeout         = 300
}

### REGISTRY KEYS ###
resource "tf-windows_registry_key" "windows_update" {
  path = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
}

resource "tf-windows_registry_key" "windows_update_au" {
  path = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
  depends_on = [tf-windows_registry_key.windows_update]
}
resource "tf-windows_registry_key" "test" {
  path = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\TOTO"
  depends_on = [tf-windows_registry_key.windows_update]
}

### REGISTRY VALUES ###
resource "tf-windows_registry_value" "wsus_server" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  name  = "WUServer"
  type  = "String"
  value = "https://wsus.ecritel.net"
  depends_on = [tf-windows_registry_key.windows_update]
}

resource "tf-windows_registry_value" "wsus_status_server" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  name  = "WUStatusServer"
  type  = "String"
  value = "https://wsus.ecritel.net"
  depends_on = [tf-windows_registry_key.windows_update]
}

resource "tf-windows_registry_value" "target_group" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  name  = "TargetGroup"
  type  = "String"
  value = "OPTAVIS"
  depends_on = [tf-windows_registry_key.windows_update]
}

resource "tf-windows_registry_value" "target_group_enabled" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"
  name  = "TargetGroupEnabled"
  type  = "DWord"
  value = "1"
  depends_on = [tf-windows_registry_key.windows_update]
}

resource "tf-windows_registry_value" "use_wsus" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
  name  = "UseWUServer"
  type  = "DWord"
  value = "1"
  depends_on = [tf-windows_registry_key.windows_update_au]
}

# Configurer les mises à jour automatiques
resource "tf-windows_registry_value" "automatic_updates" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
  name  = "NoAutoUpdate"
  type  = "DWord"
  value = "1"
  depends_on = [tf-windows_registry_key.windows_update_au]
}

# Configurer l'option de mise à jour automatique
resource "tf-windows_registry_value" "automatic_update_option" {
  path  = "HKLM:\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
  name  = "AUOptions"
  type  = "DWord"
  value = "3"
  depends_on = [tf-windows_registry_key.windows_update_au]
}