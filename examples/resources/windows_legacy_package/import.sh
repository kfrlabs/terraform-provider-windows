# Import an MSI by its ProductCode GUID (braces required, case-insensitive).
terraform import windows_legacy_package.npp '{12345678-1234-1234-1234-1234567890AB}'

# Import an EXE install by its exact DisplayName (case-sensitive, as shown
# under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*).
terraform import windows_legacy_package.vlc 'VLC media player'
