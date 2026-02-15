# Basic configuration with password authentication
provider "windows" {
  host     = "192.168.1.100"
  username = "Administrator"
  password = var.windows_password
}

# Configuration with SSH key authentication
provider "windows" {
  host     = "windows-server.example.com"
  username = "Administrator"
  key_path = "~/.ssh/id_rsa"
}

# Configuration using SSH agent
provider "windows" {
  host          = "windows-server.example.com"
  username      = "Administrator"
  use_ssh_agent = true
}

# Production configuration with connection pooling
provider "windows" {
  host     = "windows-server.example.com"
  username = "Administrator"
  password = var.windows_password

  # Connection pool settings for better performance
  enable_connection_pool = true
  pool_max_idle          = 5
  pool_max_active        = 10
  pool_idle_timeout      = 300

  # Connection timeout
  conn_timeout = 60
}

# Secure configuration with host key verification using fingerprints
provider "windows" {
  host     = "windows-server.example.com"
  username = "Administrator"
  password = var.windows_password

  # Security settings - verify host key fingerprints
  strict_host_key_checking = true
  host_key_fingerprints = [
    "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  ]

  # Connection pool
  enable_connection_pool = true
  pool_max_idle          = 3
  pool_max_active        = 5
}

# Secure configuration with known_hosts file
provider "windows" {
  host     = "windows-server.example.com"
  username = "Administrator"
  key_path = "~/.ssh/id_rsa"

  # Use known_hosts file for host key verification
  known_hosts_path         = "~/.ssh/known_hosts"
  strict_host_key_checking = true

  # Connection settings
  conn_timeout = 30
}

# Development environment configuration (relaxed security)
provider "windows" {
  host     = "192.168.56.10"
  username = "vagrant"
  password = "vagrant"

  # Disable host key checking for dev environment
  strict_host_key_checking = false

  # Disable connection pooling for easier debugging
  enable_connection_pool = false

  # Short timeout for fast failure
  conn_timeout = 15
}

# Multi-server configuration using provider aliases
provider "windows" {
  alias    = "web_server"
  host     = "web-01.example.com"
  username = "Administrator"
  password = var.web_server_password

  enable_connection_pool = true
  pool_max_idle          = 5
  pool_max_active        = 10
}

provider "windows" {
  alias    = "db_server"
  host     = "db-01.example.com"
  username = "Administrator"
  password = var.db_server_password

  enable_connection_pool = true
  pool_max_idle          = 3
  pool_max_active        = 5
}

# Resource using aliased provider
resource "windows_feature" "web_server_iis" {
  provider = windows.web_server
  feature  = "Web-Server"
}

resource "windows_feature" "db_server_sql" {
  provider = windows.db_server
  feature  = "SQL-Server-Full"
}

# High-performance configuration with aggressive connection pooling
provider "windows" {
  host     = "windows-cluster.example.com"
  username = "Administrator"
  password = var.windows_password

  # Aggressive pooling for high-throughput scenarios
  enable_connection_pool = true
  pool_max_idle          = 10
  pool_max_active        = 20
  pool_idle_timeout      = 600

  # Extended timeout for long-running operations
  conn_timeout = 120

  # Security
  strict_host_key_checking = true
  host_key_fingerprints = [
    "SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  ]
}

# Configuration using environment variables
provider "windows" {
  host     = var.windows_host
  username = var.windows_username
  # Password automatically read from WINDOWS_PASSWORD environment variable
  key_path = var.windows_key_path

  enable_connection_pool = var.enable_pool
  pool_max_idle          = var.pool_max_idle
  pool_max_active        = var.pool_max_active
}

# Complete production-ready configuration
provider "windows" {
  # Connection details
  host     = "windows-prod.example.com"
  username = "svc-terraform"
  key_path = "/etc/terraform/keys/windows-prod.pem"

  # Timeouts
  conn_timeout = 60

  # Security settings
  strict_host_key_checking = true
  host_key_fingerprints = [
    "SHA256:abcdef1234567890abcdef1234567890abcdef1234567890abcd",
    "SHA256:1234567890abcdef1234567890abcdef1234567890abcdef1234" # Backup key
  ]

  # Connection pooling for optimal performance
  enable_connection_pool = true
  pool_max_idle          = 5
  pool_max_active        = 10
  pool_idle_timeout      = 300
}