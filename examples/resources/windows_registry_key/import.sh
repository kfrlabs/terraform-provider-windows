# Import a registry key.
# Format: HIVE\PATH  (backslash-separated; quote to prevent shell interpretation)
terraform import windows_registry_key.app 'HKLM\SOFTWARE\MyApp'
