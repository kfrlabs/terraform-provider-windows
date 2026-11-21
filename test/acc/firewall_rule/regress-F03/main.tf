# Regression F03: Windows reorders address lists and drops "any" when it
# is combined with concrete addresses. The list attributes are ordered, so
# the read-back state mismatches the plan ("inconsistent result").
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_firewall_rule" "main" {
  name           = "${var.rule_prefix}-regress-f03"
  display_name   = "regress F03 address order"
  direction      = "Inbound"
  action         = "Allow"
  protocol       = "TCP"
  local_port     = ["55012"]
  local_address  = ["192.168.10.11", "10.0.0.0/8"]
  remote_address = ["203.0.113.7", "198.51.100.0/24"]
  profile        = ["Private"]
}
