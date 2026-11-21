# Regression F01: a degenerate single-port range ("<port>-<port>") is
# accepted by firewallPortValidator but Windows collapses it to "<port>",
# which used to fail Create with "inconsistent result after apply".
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "main" {
  name         = "${var.rule_prefix}-regress-f01"
  display_name = "regress F01 degenerate range"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["55014-55014"]
  profile      = ["Private"]
}
