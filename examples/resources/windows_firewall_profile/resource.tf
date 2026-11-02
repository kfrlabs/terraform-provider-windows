# Tune the Private profile in place: block inbound by default while keeping
# locally created rules honoured. Only the configured attributes are written
# (Set-NetFirewallProfile -PolicyStore PersistentStore); everything else on
# the host is left untouched.
#
# The profile carrying this SSH session is guarded fail-closed: tightening it
# without an enabled inbound Allow TCP rule for the provider port is refused
# before anything is applied. Declare the SSH allowance first (the stock
# OpenSSH-Server-In-TCP rule normally satisfies this) and order the apply:
resource "windows_firewall_rule" "ssh" {
  name         = "OpenSSH-Server-In-TCP"
  display_name = "OpenSSH SSH Server (sshd)"
  enabled      = true
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["22"]
}

resource "windows_firewall_profile" "private" {
  name                   = "Private"
  default_inbound_action = "Block"
  allow_inbound_rules    = true
  log_blocked            = true

  depends_on = [windows_firewall_rule.ssh]

  # Bound every remote operation explicitly. Without this block each operation
  # defaults to 10 minutes; a stalled PowerShell/SSH session then surfaces a
  # timeout diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "10m"
    read   = "5m"
    update = "10m"
    delete = "10m"
  }
}

# Restore-on-destroy: re-apply the pre-existing profile values captured at
# creation time when the resource is destroyed. By default destroy makes no
# remote change.
resource "windows_firewall_profile" "domain" {
  name                   = "Domain"
  log_max_size_kilobytes = 8192
  restore_on_destroy     = true
}
