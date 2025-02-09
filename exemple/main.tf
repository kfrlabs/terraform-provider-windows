terraform {
  required_providers {
    tfindows = {
      source  = "local/FranckSallet/tfindows"
    }
  }
}

provider "tfindows" {}

resource "windowsfeature" "telnet_client" {
  name          = "Telnet-Client"
  host          = "172.18.190.4"
  username      = "adminlocalecritel"
  use_ssh_agent = true
}
