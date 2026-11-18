# Regression F02 : un nom de site avec apostrophe ne doit pas casser la requete MWA.
variable "site_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefixe des objets Windows crees par ce scenario."
}

resource "windows_feature" "iis" {
  name                     = "Web-Server"
  include_management_tools = true
}

resource "windows_directory" "site" {
  path = "C:\\inetpub\\${var.site_prefix}-regress-f02"
}

resource "windows_iis_site" "site" {
  name          = "${var.site_prefix}-regress-f02-ap's"
  physical_path = windows_directory.site.path
  state         = "Stopped"

  depends_on = [windows_feature.iis]
}
