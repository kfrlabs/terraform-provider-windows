# Regression F03: https binding with a non-default store and NO certificate
# must warn and apply cleanly (no "inconsistent result after apply").
variable "site_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefix of Windows objects created by this scenario."
}

resource "windows_feature" "iis" {
  name                     = "Web-Server"
  include_management_tools = true
}

resource "windows_iis_site" "host" {
  name          = "${var.site_prefix}-regress-f03"
  physical_path = "C:\\inetpub\\wwwroot"

  depends_on = [windows_feature.iis]
}

resource "windows_iis_binding" "https" {
  site_name              = windows_iis_site.host.name
  protocol               = "https"
  port                   = 18244
  host_header            = "${var.site_prefix}-regress-f03.example.com"
  certificate_store_name = "WebHosting"
}
