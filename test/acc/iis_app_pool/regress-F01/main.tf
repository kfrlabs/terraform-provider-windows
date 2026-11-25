# Regression F01 : recycling_periodic_restart_minutes au-dela du plafond IIS
# (300 j = 432000 min) doit etre rejete au plan, pas a l'apply.
variable "pool_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_iis_app_pool" "test" {
  name                               = "${var.pool_prefix}-regress-f01"
  recycling_periodic_restart_minutes = 525600
}
