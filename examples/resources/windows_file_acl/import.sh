# windows_file_acl is imported by the absolute path of the secured target.
# The target must already exist: this resource manages a security descriptor,
# never the existence of the file or directory it belongs to.
terraform import windows_file_acl.app_config 'C:\inetpub\wwwroot\app\appsettings.json'

# Directories are imported the same way.
terraform import windows_file_acl.data_dir 'C:\ProgramData\app\data'

# An imported resource always comes back in authoritative mode, with one
# access_rule block per explicit entry of the observed DACL. Inherited entries
# are not adopted as blocks: they are reported in effective_access_rules and
# remain governed by the parent.
#
# The adopted blocks carry the canonical identity and the keyword decomposition
# of each access mask, which may not be spelled the way your configuration
# spells it: a SID is imported as a SID, and Modify is imported as Modify even
# if you wrote ["Read", "Write", "Delete"]. Run a plan after importing; it is
# clean as long as the effective rights match, because comparison is done on
# the access mask rather than on the keywords.
#
# If the target is protected from inheritance, inheritance_enabled comes back
# as false. Note that preserve_inherited_on_protect is ignored in authoritative
# mode, so declaring the entries you want to keep is mandatory.
terraform plan

# UNC paths work, provided the SSH account can reach the share (a local account
# normally cannot: Kerberos double hop).
terraform import windows_file_acl.shared '\\fileserver\deploy'
