# Regression scenario for F02: rights keywords in non-canonical case must be
# accepted (case-insensitive canonicalisation) and duplicates that differ
# only by case must merge, so apply succeeds and the next plan is empty.
variable "name_prefix" {
  type    = string
  default = "tfacc-f02"
}

resource "windows_file" "app" {
  path    = "C:\\${var.name_prefix}\\app.conf"
  content = "rights-case"
}

resource "windows_file_acl" "test" {
  path                = windows_file.app.path
  inheritance_enabled = false

  access_rule {
    identity = "S-1-5-32-544"
    rights   = ["fullcontrol"]
  }

  access_rule {
    identity = "NT AUTHORITY\\SYSTEM"
    rights   = ["read", "READ"]
  }
}
