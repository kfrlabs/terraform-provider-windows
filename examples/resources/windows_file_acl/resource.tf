terraform {
  required_providers {
    windows = {
      source  = "kfrlabs/windows"
      version = "~> 0.1"
    }
  }
}

provider "windows" {
  host     = "win01.example.local"
  username = "Administrator"
  password = var.windows_password
}

# Lock down a configuration file: inheritance disabled, and exactly three
# explicit entries. Because the mode is authoritative, any entry added by hand
# afterwards shows up as drift and is removed on the next apply.
resource "windows_file_acl" "app_config" {
  path  = "C:\\inetpub\\wwwroot\\app\\appsettings.json"
  owner = "BUILTIN\\Administrators"

  inheritance_enabled = false

  access_rule {
    identity = "NT AUTHORITY\\SYSTEM"
    rights   = ["FullControl"]
  }

  access_rule {
    identity = "BUILTIN\\Administrators"
    rights   = ["FullControl"]
  }

  access_rule {
    identity = "IIS APPPOOL\\AppPool"
    rights   = ["Read"]
  }
}

# Secure a file this provider also creates. windows_file preserves the security
# descriptor on every content update, so the two resources cohabit on the same
# path without fighting.
resource "windows_file" "secrets" {
  path    = "C:\\ProgramData\\app\\secrets.config"
  content = var.secrets_document
}

resource "windows_file_acl" "secrets" {
  path                = windows_file.secrets.path
  inheritance_enabled = false

  access_rule {
    identity = "NT AUTHORITY\\SYSTEM"
    rights   = ["FullControl"]
  }

  access_rule {
    identity = "BUILTIN\\Administrators"
    rights   = ["FullControl"]
  }
}

# A data directory. Inheritance flags only mean something on a directory:
# container_object propagates to both subdirectories and files.
resource "windows_file_acl" "data_dir" {
  path = "C:\\ProgramData\\app\\data"

  access_rule {
    identity    = "DOMAIN\\svc_app"
    rights      = ["Modify"]
    inheritance = "container_object"
  }

  # Grant read on subdirectories only, never on the directory itself.
  access_rule {
    identity    = "DOMAIN\\Auditors"
    rights      = ["ReadAndExecute"]
    inheritance = "container"
    propagation = "inherit_only"
  }

  # Deny entries are written before allow entries, in the canonical Windows
  # order, whatever order the blocks appear in.
  access_rule {
    identity = "BUILTIN\\Guests"
    rights   = ["FullControl"]
    type     = "deny"
  }
}

# Additive mode: enforce one entry and leave the rest of the DACL alone. Use it
# on a path whose permissions are partly owned by someone else, such as a
# directory an installer manages.
resource "windows_file_acl" "shared_logs" {
  path = "C:\\ProgramData\\vendor\\logs"
  mode = "additive"

  access_rule {
    identity    = "DOMAIN\\svc_monitoring"
    rights      = ["Read"]
    inheritance = "container_object"
  }
}

# Identities may be SIDs, which is what you want for well-known groups: a SID
# is stable across locales, and BUILTIN\Administrators is not called that on a
# non-English install.
resource "windows_file_acl" "by_sid" {
  path = "C:\\ProgramData\\app\\state.db"

  access_rule {
    identity = "S-1-5-32-544" # BUILTIN\Administrators
    rights   = ["FullControl"]
  }

  access_rule {
    identity = "S-1-5-18" # NT AUTHORITY\SYSTEM
    rights   = ["FullControl"]
  }
}

# The observed descriptor is always available for diagnostics.
output "app_config_sddl" {
  value = windows_file_acl.app_config.sddl
}

output "app_config_effective_dacl" {
  description = "Every DACL entry, inherited ones included."
  value = [
    for rule in windows_file_acl.app_config.effective_access_rules :
    "${rule.identity} (${rule.identity_sid}): ${rule.type} ${join(",", rule.rights)} inherited=${rule.inherited}"
  ]
}
