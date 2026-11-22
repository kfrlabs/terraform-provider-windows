# Regression F02 : recycling_schedule avec secondes non nulles doit etre
# rejete au plan (IIS exige des entrees a la minute ronde, granularite 60 s).
variable "pool_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_iis_app_pool" "test" {
  name               = "${var.pool_prefix}-regress-f02"
  recycling_schedule = ["05:15:30"]
}
