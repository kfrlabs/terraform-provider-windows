# Firewall: inbound allow + outbound block (mirrors the documented examples).
#
# Gated behind enable_firewall_tests: Windows Firewall with Advanced Security
# is unavailable inside Windows containers (New-NetFirewallRule fails with
# "There are no more endpoints available from the endpoint mapper"), so this
# stays off against tfacc-win. Enable against a full Windows host/VM.
resource "windows_firewall_rule" "allow_inbound" {
  count = var.enable_firewall_tests ? 1 : 0

  name         = "Allow-CliTest-${var.test_suffix}"
  display_name = "Allow CLI-Test Inbound (${var.test_suffix})"
  description  = "Inbound TCP 8443 for the terraform-cli fixture - managed by Terraform."
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["8443"]
  profile      = ["Any"]
}

resource "windows_firewall_rule" "block_egress" {
  count = var.enable_firewall_tests ? 1 : 0

  name           = "Block-CliTest-Egress-${var.test_suffix}"
  display_name   = "Block CLI-Test Egress (${var.test_suffix})"
  description    = "Blocks outbound traffic to a documentation/test-only subnet."
  direction      = "Outbound"
  action         = "Block"
  remote_address = ["198.51.100.0/24"]
}
