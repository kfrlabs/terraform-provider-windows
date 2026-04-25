# Import a windows_local_group by group name (EC-10).
# The import ID auto-detection:
#   - Starts with "S-"  → treated as a SID  (Get-LocalGroup -SID)
#   - Anything else     → treated as a name  (Get-LocalGroup -Name)
# After import the resource ID is always the group SID, not the import string.

# By name:
terraform import windows_local_group.app_admins AppAdmins

# By SID (value starts with "S-"):
terraform import windows_local_group.app_admins S-1-5-21-1234567890-987654321-1122334455-1001

# Retrieve the SID of a group on the target host (run on the Windows machine):
# (Get-LocalGroup -Name "AppAdmins").SID.Value
