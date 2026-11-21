# Regression F02: Windows canonicalises the protocol keyword
# ("tcp" -> "TCP", "1" -> "ICMPv4", "ANY" -> "Any"), which used to fail
# Create with "inconsistent result after apply".
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "lower" {
  name         = "${var.rule_prefix}-regress-f02-lower"
  display_name = "regress F02 lowercase tcp"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "tcp"
  local_port   = ["55011"]
  profile      = ["Private"]
}

resource "windows_firewall_rule" "numeric" {
  name         = "${var.rule_prefix}-regress-f02-num"
  display_name = "regress F02 numeric 1"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "1"
  profile      = ["Private"]
}

resource "windows_firewall_rule" "anykw" {
  name           = "${var.rule_prefix}-regress-f02-any"
  display_name   = "regress F02 uppercase ANY"
  direction      = "Outbound"
  action         = "Block"
  protocol       = "ANY"
  remote_address = ["203.0.113.0/24"]
}
