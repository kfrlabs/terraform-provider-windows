# Import a share by its SMB share name.
# ID format: <name>
# Special (administrative) shares (ADMIN$, C$, IPC$) are owned by Windows and
# cannot be imported. Access sets start unmanaged (null) after import: declare
# them to take over the access list authoritatively.
terraform import windows_smb_share.finance 'Finance'
