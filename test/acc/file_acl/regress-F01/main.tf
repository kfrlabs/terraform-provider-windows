# Regression scenario for F01: importing a protected target whose DACL is
# exactly one explicit FullControl entry must yield an empty plan when the
# config describes that descriptor (SID spelling, preserve=false).
variable "name_prefix" {
  type    = string
  default = "tfacc-f01"
}

resource "windows_file" "app" {
  path    = "C:\\${var.name_prefix}\\app.conf"
  content = "import-me"
}

resource "windows_file_acl" "test" {
  path                        = windows_file.app.path
  inheritance_enabled           = false
  preserve_inherited_on_protect = false

  access_rule {
    identity = "S-1-5-32-544"
    rights   = ["FullControl"]
  }
}
