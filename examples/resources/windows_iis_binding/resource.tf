# Manage one IIS binding on a site: only the in-place attributes
# (require_sni, certificate_thumbprint, certificate_store_name) are written
# after creation; the identity (site, protocol, IP, port, host) is ForceNew.
#
# The site must already exist (windows_iis_site). Certificates live in
# Cert:\LocalMachine\<store> and are managed by windows_certificate — they
# are never created implicitly, and a certificate without a private key is
# refused. Binding the SSH management port is refused fail-closed
# (would_lock_out).
#
# Requires IIS on the target host (WebAdministration module): install it
# with windows_feature first (Web-Server; add Web-Mgmt-Console /
# Web-Scripting-Tools for the module on Server Core).
resource "windows_feature" "iis" {
  name                     = "Web-Server"
  include_management_tools = true
}

resource "windows_iis_site" "web" {
  name          = "web"
  physical_path = "C:\\inetpub\\wwwroot"

  depends_on = [windows_feature.iis]
}

# Plain HTTP binding (no certificate).
resource "windows_iis_binding" "http" {
  site_name   = windows_iis_site.web.name
  protocol    = "http"
  ip_address  = "*"
  port        = 80
  host_header = "example.com"

  depends_on = [windows_feature.iis]

  # Bound every remote operation explicitly. Without this block each operation
  # defaults to 10 minutes; a stalled PowerShell/SSH session then surfaces a
  # timeout diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "10m"
    read   = "10m"
    update = "10m"
    delete = "10m"
  }
}

# HTTPS binding with SNI: require_sni needs a host header, and the
# certificate must already carry a private key.
resource "windows_iis_binding" "https" {
  site_name   = windows_iis_site.web.name
  protocol    = "https"
  ip_address  = "*"
  port        = 443
  host_header = "example.com"

  require_sni            = true
  certificate_thumbprint = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
  certificate_store_name = "My"

  depends_on = [windows_feature.iis]

  timeouts = {
    create = "10m"
    read   = "10m"
    update = "10m"
    delete = "10m"
  }
}
