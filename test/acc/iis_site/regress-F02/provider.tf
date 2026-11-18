terraform {
  required_providers {
    windows = { source = "kfrlabs/windows" }
  }
}

provider "windows" {
  host             = "172.18.122.203"
  port             = 22
  username         = "adminlocalecritel"
  private_key_path = "C:/Users/adminlocalecritel/.ssh/id_lab203_rsa"
}
