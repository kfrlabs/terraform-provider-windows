# Regression F02: a single IPv6 "::1" binding must round-trip cleanly.
# binding_information must read back bracketed ("[::1]:<port>:<host>").
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
  name          = "${var.site_prefix}-regress-f02"
  physical_path = "C:\\inetpub\\wwwroot"

  depends_on = [windows_feature.iis]
}

resource "windows_iis_binding" "v6" {
  site_name   = windows_iis_site.host.name
  protocol    = "http"
  ip_address  = "::1"
  port        = 18243
  host_header = "${var.site_prefix}-regress-f02-v6.example.com"
}
