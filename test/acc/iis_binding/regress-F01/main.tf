# Regression F01: two bindings on one site must apply cleanly under default
# (parallel) Terraform parallelism — no NullReference race.
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
  name          = "${var.site_prefix}-regress-f01"
  physical_path = "C:\\inetpub\\wwwroot"

  depends_on = [windows_feature.iis]
}

resource "windows_iis_binding" "a" {
  site_name   = windows_iis_site.host.name
  protocol    = "http"
  port        = 18241
  host_header = "${var.site_prefix}-regress-f01-a.example.com"
}

resource "windows_iis_binding" "b" {
  site_name   = windows_iis_site.host.name
  protocol    = "http"
  port        = 18242
  host_header = "${var.site_prefix}-regress-f01-b.example.com"
}
