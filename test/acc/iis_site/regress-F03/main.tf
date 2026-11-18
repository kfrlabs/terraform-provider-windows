# Regression F03 : conflit de site_id en creations paralleles doit remonter id_conflict.
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
  path = "C:\\inetpub\\${var.site_prefix}-regress-f03"
}

# Pas de depends_on entre site_a et site_b : Terraform les cree en parallele
# (comme dans le scenario 20 d'origine), ce qui fait passer les deux gardes
# pre-flight $idClash avant que l'un des New-Item ne gagne.
resource "windows_iis_site" "site_a" {
  name          = "${var.site_prefix}-regress-f03-a"
  site_id       = 42391
  physical_path = windows_directory.site.path
  state         = "Stopped"

  depends_on = [windows_feature.iis]
}

resource "windows_iis_site" "site_b" {
  name          = "${var.site_prefix}-regress-f03-b"
  site_id       = 42391
  physical_path = windows_directory.site.path
  state         = "Stopped"

  depends_on = [windows_feature.iis]
}
