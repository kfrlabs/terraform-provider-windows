resource "windows_firewall_rule" "allow_app_inbound" {
  name         = "Allow-PushedTest-${var.test_suffix}"
  display_name = "Allow Pushed-Test Inbound (${var.test_suffix})"
  description  = "Inbound TCP 8443 for the pushed-test fixture — managed by Terraform."
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["8443"]
  profile      = ["Any"]
}

resource "windows_firewall_rule" "block_app_outbound" {
  name           = "Block-PushedTest-Egress-${var.test_suffix}"
  display_name   = "Block Pushed-Test Egress (${var.test_suffix})"
  description    = "Blocks outbound traffic to a documentation/test-only subnet — managed by Terraform."
  direction      = "Outbound"
  action         = "Block"
  remote_address = ["198.51.100.0/24"]
}
