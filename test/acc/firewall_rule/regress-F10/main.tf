# Regression F10 (run 2611210928, scenario 01) : le protocole IGMP n'a pas
# de mot-cle Windows — seule la forme numerique '2' est acceptee et elle est
# conservee verbatim. '58'/'Icmpv6' (temoins) se replient vers 'ICMPv6'.
variable "rule_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

# Forme numerique : Windows la stocke telle quelle ('2', pas 'IGMP').
resource "windows_firewall_rule" "two" {
  name         = "${var.rule_prefix}-regress-f10-two"
  display_name = "regress F10 numeric 2"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "2"
  profile      = ["Private"]
}

# Mot-cle insensible a la casse : doit se replier vers '2' (Windows rejette
# le mot-cle 'IGMP' avec 'The protocol is invalid').
resource "windows_firewall_rule" "igmp" {
  name         = "${var.rule_prefix}-regress-f10-igmp"
  display_name = "regress F10 keyword igmp"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "igmp"
  profile      = ["Private"]
}

# Temoins : alias numerique et casse mixte vers le mot-cle ICMPv6.
resource "windows_firewall_rule" "fift8" {
  name         = "${var.rule_prefix}-regress-f10-58"
  display_name = "regress F10 numeric 58"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "58"
  profile      = ["Private"]
}

resource "windows_firewall_rule" "mix" {
  name         = "${var.rule_prefix}-regress-f10-mix"
  display_name = "regress F10 mixed Icmpv6"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "Icmpv6"
  profile      = ["Private"]
}
