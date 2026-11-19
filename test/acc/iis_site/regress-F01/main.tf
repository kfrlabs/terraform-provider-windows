# Regression F01 : site_id = 4294967295 (maximum uint32 accepte par le
# validateur) ne doit pas produire "inconsistent result after apply".
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
  path = "C:\\inetpub\\${var.site_prefix}-regress-f01"
}

resource "windows_iis_site" "site" {
  name          = "${var.site_prefix}-regress-f01"
  site_id       = 4294967295
  physical_path = windows_directory.site.path
  state         = "Stopped"

  depends_on = [windows_feature.iis]
}
