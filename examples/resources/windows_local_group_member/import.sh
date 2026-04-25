# Import a windows_local_group_member using the composite ID "<group>/<member>".
#
# Both sides of the separator accept either a name or a SID:
#   - Values starting with "S-" are treated as SIDs.
#   - Anything else is treated as a name (group name or member name/UPN).
#
# After import the resource ID is always "<group_sid>/<member_sid>",
# regardless of which format was used for the import ID.

# By group name / member NetBIOS name (shell single-quotes avoid backslash escaping):
terraform import windows_local_group_member.example 'Administrators/DOMAIN\jdoe'

# By group SID / member SID (most stable form — immune to renames):
terraform import windows_local_group_member.example "S-1-5-32-544/S-1-5-21-1234567890-987654321-1122334455-1001"
