# A finance share with access-based enumeration, no offline caching and
# encrypted transport. The shared directory must already exist (manage it
# with windows_directory); it is never created here.
resource "windows_smb_share" "finance" {
  name                    = "Finance"
  path                    = "D:\\Shares\\Finance"
  description             = "Finance department share"
  folder_enumeration_mode = "AccessBased"
  caching_mode            = "None"
  encrypt_data            = true
  full_access             = ["BUILTIN\\Administrators"]
  change_access           = ["FINANCE\\Managers"]
  read_access             = ["Everyone"]
}

# An unmanaged share: with all four access sets omitted the host access list
# is left untouched and never diffed. Declare any of the sets to take over
# authoritatively (empty = revoke everything at that level).
resource "windows_smb_share" "scratch" {
  name = "Scratch"
  path = "D:\\Shares\\Scratch"

  # Bound every remote operation explicitly. Without this block each operation
  # defaults to 10 minutes; a stalled PowerShell/SSH session then surfaces a
  # timeout diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "10m"
    read   = "5m"
    update = "10m"
    delete = "10m"
  }
}
