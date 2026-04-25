# Import a named registry value.
# Format: HIVE\PATH\NAME  (backslash-separated; quote to prevent shell interpretation)
terraform import windows_registry_value.reg_sz 'HKLM\SOFTWARE\MyApp\Version'

# Import a REG_EXPAND_SZ value.
terraform import windows_registry_value.reg_expand_sz 'HKLM\SOFTWARE\MyApp\InstallDir'

# Import a REG_MULTI_SZ value.
terraform import windows_registry_value.reg_multi_sz 'HKLM\SOFTWARE\MyApp\SearchPaths'

# Import a REG_DWORD value.
terraform import windows_registry_value.reg_dword 'HKLM\SOFTWARE\MyApp\MaxRetries'

# Import a REG_QWORD value.
terraform import windows_registry_value.reg_qword 'HKLM\SOFTWARE\MyApp\CacheSizeBytes'

# Import a REG_BINARY value.
terraform import windows_registry_value.reg_binary 'HKLM\SOFTWARE\MyApp\BinaryConfig'

# Import a REG_NONE value.
terraform import windows_registry_value.reg_none 'HKLM\SOFTWARE\MyApp\Marker'

# Import the Default (unnamed) value.
# The import ID MUST end with a trailing backslash when name="".
# Quotes are required on most shells to pass the trailing backslash literally.
terraform import windows_registry_value.default_value 'HKCU\SOFTWARE\MyApp\'
