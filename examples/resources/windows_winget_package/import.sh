# Import a package from the default "winget" source.
# Format: <source>:<package_id>
terraform import windows_winget_package.vscode winget:Microsoft.VisualStudioCode

# Import a package from the Microsoft Store source.
terraform import windows_winget_package.windows_terminal msstore:9N0DX20HK701
