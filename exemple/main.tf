terraform {
  required_providers {
    tf-windows = {
      source = "local/FranckSallet/tf-windows"
    }
  }
}

provider "tf-windows" {}

resource "tf-windows_feature" "powershell" {
  host          = "172.18.190.4"
  username      = "adminlocalecritel"
  use_ssh_agent = true
  features      = ["PowerShellRoot", "Powershell"]
}
