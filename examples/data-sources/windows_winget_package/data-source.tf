# Look up an installed winget-managed package on the target Windows host.
data "windows_winget_package" "vscode" {
  package_id = "Microsoft.VisualStudioCode"
  source     = "winget"
}

output "winget_package_info" {
  value = data.windows_winget_package.vscode
}
