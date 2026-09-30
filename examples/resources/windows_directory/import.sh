# Import an existing directory by its absolute Windows path.
terraform import windows_directory.application 'C:\ProgramData\Example\Application'

# UNC paths are supported when the SSH account can access the share.
# terraform import windows_directory.shared '\\fileserver\deploy\Application'
