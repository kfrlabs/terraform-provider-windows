# Regression F08: plan must be empty after importing a rule whose
# configuration uses non-canonical spellings (lowercase protocol,
# degenerate range + duplicate, unsorted addresses). Import stores the
# Windows-canonical state; without plan-time folding toward prior state the
# next plan shows a spurious diff (protocol/local_port/remote_address).
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "main" {
  name         = "${var.rule_prefix}-regress-f08"
  display_name = "regress F08 import canonical probe"
  description  = "F08 import plan-empty probe"
  direction    = "Inbound"
  action       = "Allow"
  # Lowercase keyword -> UDP (F02); degenerate range + duplicate (F01);
  # unsorted remote addresses (F03). remote_port already canonical (witness).
  protocol       = "udp"
  local_port     = ["55312", "55311-55311", "55311"]
  remote_port    = ["55313"]
  local_address  = ["192.0.2.0/24"]
  remote_address = ["203.0.113.15", "198.51.100.0/24"]
}
