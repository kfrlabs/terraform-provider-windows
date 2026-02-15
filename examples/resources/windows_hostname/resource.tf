# Basic hostname change without restart
resource "windows_hostname" "example" {
  hostname = "WIN-SERVER-01"
}

# Hostname change with automatic restart
resource "windows_hostname" "example_with_restart" {
  hostname = "WIN-SERVER-02"
  restart  = true
}

# Hostname change with custom timeout
resource "windows_hostname" "example_custom_timeout" {
  hostname        = "WIN-SERVER-03"
  restart         = true
  command_timeout = 600
}