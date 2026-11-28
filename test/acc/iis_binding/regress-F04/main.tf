# Regression F04 (negative): bracketed ip_address must be rejected at plan
# time with a diagnostic that names brackets. Nothing is created.
variable "site_prefix" {
  type        = string
  default     = "tfacc"
  description = "Prefix of Windows objects created by this scenario."
}

resource "windows_iis_binding" "bad" {
  site_name   = "${var.site_prefix}-regress-f04-nv"
  protocol    = "http"
  ip_address  = "[::1]"
  port        = 18245
  host_header = "${var.site_prefix}-regress-f04.example.com"
}
