# Regression F11 (run 2611210928, scenario 04) : suffixes d'hote /32 et /128.
# Windows depouille le suffixe d'une route d'hote et stocke l'IP nue
# ('192.0.2.1/32' -> '192.0.2.1', '2001:db8:1::5/128' -> '2001:db8:1::5').
# Le plan doit donc se replier vers la forme nue pour rester coherent.
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "host32" {
  name           = "${var.rule_prefix}-regress-f11-32"
  display_name   = "regress F11 host /32"
  direction      = "Inbound"
  action         = "Allow"
  local_address  = ["192.0.2.1/32", "10.128.0.0/16"]
  remote_address = ["Any"]
  profile        = ["Private"]
}

resource "windows_firewall_rule" "host128" {
  name           = "${var.rule_prefix}-regress-f11-128"
  display_name   = "regress F11 host /128"
  direction      = "Inbound"
  action         = "Allow"
  local_address  = ["Any"]
  remote_address = ["2001:db8:1::5/128", "10.200.0.0/16"]
  profile        = ["Private"]
}
