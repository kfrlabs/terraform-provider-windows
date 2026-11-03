# Firewall (rules + profile) and host networking (DNS, IPs, routes). Rule
# shapes mirror the documented examples.
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

  # CLI-level coverage for the timeouts block: parsed by validate and the
  # mocked suite on every PR (offline CI job), honoured on --apply runs.
  # Written with `=` (not a block): like every other SingleNestedAttribute
  # in this provider, `timeouts` only accepts the assignment form.
  timeouts = {
    create = "5m"
    delete = "5m"
  }
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

# SSH allowance for the provider session. The windows_firewall_profile fixture
# below tightens the Private profile in place: the provider refuses that
# fail-closed unless an enabled inbound Allow rule for the provider port
# exists first, so declare it here and order the profile after it.
resource "windows_firewall_rule" "ssh_allow" {
  count = var.enable_firewall_tests ? 1 : 0

  name         = "Allow-CliTest-SSH-${var.test_suffix}"
  display_name = "Allow CLI-Test SSH (${var.test_suffix})"
  description  = "Inbound SSH for the terraform-cli fixture - managed by Terraform."
  direction    = "Inbound"
  action       = "Allow"
  enabled      = true
  protocol     = "TCP"
  local_port   = [tostring(var.windows_port)]
  profile      = ["Any"]
}

# Private profile tuned in place (log-only changes here: no lockout risk).
# Only the configured attributes are written; everything else on the host is
# left untouched. restore_on_destroy re-applies the pre-existing values on
# destroy; otherwise destroy is a no-op.
resource "windows_firewall_profile" "fixture" {
  count = var.enable_firewall_tests ? 1 : 0

  name                   = "Private"
  log_blocked            = true
  log_max_size_kilobytes = 8192
  restore_on_destroy     = true

  depends_on = [windows_firewall_rule.ssh_allow]

  # CLI-level coverage for the timeouts block: parsed by validate and the
  # mocked suite on every PR (offline CI job), honoured on --apply runs.
  # Written with `=` (not a block): like every other SingleNestedAttribute
  # in this provider, `timeouts` only accepts the assignment form.
  timeouts = {
    create = "5m"
    delete = "5m"
  }
}

# DNS client on the secondary NIC (the management NIC keeps its own
# resolvers). Documentation ranges only (RFC 5737 / RFC 3849). Omitting a
# family leaves it unmanaged; reset_on_destroy returns the managed families
# to automatic (DHCP) on destroy.
resource "windows_dns_client" "secondary" {
  count = var.enable_network_config_tests ? 1 : 0

  interface_alias            = "Ethernet 2"
  ipv4_server_addresses      = ["192.0.2.53", "198.51.100.53"]
  ipv6_server_addresses      = ["2001:db8::53"]
  connection_specific_suffix = "corp.example.com"

  reset_on_destroy = true

  # CLI-level coverage for the timeouts block (see above).
  timeouts = {
    create = "10m"
    delete = "10m"
  }
}

# Static IPv4 address on the secondary NIC (storage network). The interface
# must already exist; disable_dhcp is required when the interface still has
# DHCP enabled. The default gateway is NOT managed here (see net_route).
resource "windows_net_ip_address" "storage" {
  count = var.enable_network_config_tests ? 1 : 0

  interface_alias = "Ethernet 2"
  ip_address      = "192.0.2.10" # documentation range, RFC 5737
  prefix_length   = 24
  disable_dhcp    = true

  # CLI-level coverage for the timeouts block (see above).
  timeouts = {
    create = "10m"
    delete = "10m"
  }
}

# Static route to a remote network (storage network) through a gateway on
# the same subnet. The gateway must be on-link on the interface.
resource "windows_net_route" "backup" {
  count = var.enable_network_config_tests ? 1 : 0

  destination_prefix = "198.51.100.0/24" # documentation range, RFC 5737
  interface_alias    = "Ethernet 2"
  next_hop           = "192.0.2.1"
  route_metric       = 10

  # CLI-level coverage for the timeouts block (see above).
  timeouts = {
    create = "10m"
    delete = "10m"
  }
}
