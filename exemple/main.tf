terraform {
  required_providers {
    tf-windows = {
      source = "local/FranckSallet/tf-windows"
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
}
