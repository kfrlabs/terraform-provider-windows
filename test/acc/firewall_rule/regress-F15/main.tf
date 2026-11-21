# Regression F15 (run 2611211023, scenario 03-adv-maskform-output) : CIDR
# avec bits d'hote + restitution Windows en forme masque pointille.
# Windows canonise les bits d'hote (198.51.100.0/16 -> 198.51.0.0/255.255.0.0)
# que le provider convertit en 198.51.0.0/16 sans canoniser le plan, d'ou
# un `inconsistent result after apply` sur .remote_address[0].
# Le local 203.0.113.0/24 (deja adresse reseau) est le temoin stable.
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "main" {
  name           = "${var.rule_prefix}-regress-f15"
  display_name   = "regress F15 host-bits canonicalisation"
  direction      = "Inbound"
  action         = "Allow"
  profile        = ["Private"]
  local_address  = ["203.0.113.0/24"]
  remote_address = ["198.51.100.0/16", "2001:db8:2::/64"]
}
