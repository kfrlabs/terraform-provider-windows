# Regression F04 step2: back to minimal, description returns to null.
# The Update must clear Description on 203, otherwise the read-back state
# mismatches the plan ("inconsistent result after apply").
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "main" {
  name         = "${var.rule_prefix}-regress-f04"
  display_name = "regress F04 transitions"
  direction    = "Inbound"
  action       = "Allow"
}
