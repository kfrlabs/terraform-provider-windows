# Regression F05 : recycling_periodic_restart_minutes = 432000 (300 j, borne
# F01 valide) doit survivre a l'aller-retour — l'ecriture reussit sur 203
# (periodicRestart.time = 300.00:00:00) et la relecture doit retourner 432000,
# pas 0.
variable "pool_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_iis_app_pool" "test" {
  name                               = "${var.pool_prefix}-regress-f05"
  recycling_periodic_restart_minutes = 432000
}

output "restart_minutes" {
  value = windows_iis_app_pool.test.recycling_periodic_restart_minutes
}
