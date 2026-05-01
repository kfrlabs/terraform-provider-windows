terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host      = var.windows_host
  username  = var.windows_username
  password  = var.windows_password
  auth_type = "ntlm"
}

# Minimal example: allow inbound HTTPS traffic.
resource "windows_firewall_rule" "allow_https" {
  name         = "Allow-Inbound-HTTPS"
  display_name = "Allow Inbound HTTPS"
  description  = "Permits inbound TCP traffic on port 443 — managed by Terraform."
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["443"]
  profile      = ["Domain", "Private"]
}

# Block outbound access to a specific remote subnet.
resource "windows_firewall_rule" "block_outbound" {
  name           = "Block-Outbound-Rogue-IP"
  display_name   = "Block Outbound to 198.51.100.0/24"
  description    = "Blocks outbound traffic to a rogue subnet."
  direction      = "Outbound"
  action         = "Block"
  remote_address = ["198.51.100.0/24"]
}

# Application-scoped rule: allow traffic only for a specific executable.
resource "windows_firewall_rule" "allow_myapp" {
  name         = "Allow-MyApp-Outbound"
  display_name = "Allow MyApp Outbound"
  direction    = "Outbound"
  action       = "Allow"
  program      = "C:\\Program Files\\MyApp\\myapp.exe"
  profile      = ["Any"]
}

# ICMP rule: allow ICMPv4 pings from any address.
resource "windows_firewall_rule" "allow_ping" {
  name         = "Allow-ICMPv4-In"
  display_name = "Allow ICMPv4 Echo Request (Ping)"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "ICMPv4"
}

# Group example: link related rules for bulk enable/disable.
resource "windows_firewall_rule" "web_http" {
  name         = "Allow-Inbound-HTTP"
  display_name = "Allow Inbound HTTP"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["80"]
  group        = "WebServer"
}

resource "windows_firewall_rule" "web_https" {
  name         = "Allow-Inbound-HTTPS-Grp"
  display_name = "Allow Inbound HTTPS (group)"
  direction    = "Inbound"
  action       = "Allow"
  protocol     = "TCP"
  local_port   = ["443"]
  group        = "WebServer"
}
