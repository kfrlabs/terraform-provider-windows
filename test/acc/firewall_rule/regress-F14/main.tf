# Regression F14 (run 2611210928, scenario 10, negatif) : CV-3 Any melange.
# Les deux plans doivent echouer avec "Invalid address combination" (exit 1),
# sans rien creer sur 203. Verrouille firewallRuleAddressAnyValidator,
# qui n'avait aucune couverture versionnee (F06 cycle 2 : constate en run
# seulement, jamais fige en regress).
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "any_local" {
  name           = "${var.rule_prefix}-regress-f14-l"
  display_name   = "regress F14 CV-3 local"
  direction      = "Inbound"
  action         = "Allow"
  local_address  = ["Any", "10.0.0.0/8"]
  remote_address = ["192.0.2.0/24"]
  profile        = ["Private"]
}

resource "windows_firewall_rule" "any_remote" {
  name           = "${var.rule_prefix}-regress-f14-r"
  display_name   = "regress F14 CV-3 remote"
  direction      = "Inbound"
  action         = "Allow"
  local_address  = ["192.0.2.0/24"]
  remote_address = ["any", "192.0.2.0/24"]
  profile        = ["Private"]
}
