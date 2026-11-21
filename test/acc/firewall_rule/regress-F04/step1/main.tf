# Regression F04 step1: full config WITH description.
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "main" {
  name         = "${var.rule_prefix}-regress-f04"
  display_name = "regress F04 transitions"
  description  = "regress F04 description step1"
  direction    = "Inbound"
  action       = "Allow"
}
