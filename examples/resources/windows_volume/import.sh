# Import an existing volume by its Get-Volume UniqueId.
terraform import windows_volume.data '\\?\Volume{11111111-2222-3333-4444-555555555555}\'

# Import an existing volume by drive letter (the trailing colon is optional).
terraform import windows_volume.data 'E:'
