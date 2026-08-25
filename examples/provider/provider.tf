terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.0"
    }
  }
}

# Recommended: public-key authentication, with the server's identity verified
# against the local known_hosts file (the default).
provider "windows" {
  host             = var.windows_host
  username         = var.windows_username
  private_key_path = "~/.ssh/id_ed25519"
}

# In CI or Terraform Cloud there is usually no known_hosts file, so pin the
# server key directly. Obtain it with `ssh-keyscan <host>` and verify the
# fingerprint out of band before trusting it.
provider "windows" {
  alias = "ci"

  host        = var.windows_host
  username    = var.windows_username
  private_key = var.windows_private_key
  host_key    = var.windows_host_key # "ssh-ed25519 AAAAC3Nz..."
}

# Password authentication remains supported, and host verification still
# applies. Prefer keys where the target allows it.
provider "windows" {
  alias = "password"

  host             = var.windows_host
  username         = var.windows_username
  password         = var.windows_password
  known_hosts_path = "/etc/ssh/known_hosts"
}
