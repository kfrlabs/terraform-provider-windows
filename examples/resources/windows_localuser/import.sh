# Import a basic user
terraform import windows_localuser.basic "basicuser"

# Import local administrator
terraform import windows_localuser.admin "localadmin"

# Import service account
terraform import windows_localuser.service_account "svc_webapp"

# Import disabled user
terraform import windows_localuser.disabled_user "future_user"

# Import temporary user
terraform import windows_localuser.temp_user "tempuser"

# Import existing user
terraform import windows_localuser.existing_user "existinguser"

# Import built-in Administrator account
terraform import windows_localuser.administrator "Administrator"

# Import built-in Guest account
terraform import windows_localuser.guest "Guest"

# Import multiple users using for_each
terraform import 'windows_localuser.developer["dev1"]' "dev1"
terraform import 'windows_localuser.developer["dev2"]' "dev2"
terraform import 'windows_localuser.developer["dev3"]' "dev3"

# Import backup administrator
terraform import windows_localuser.backup_admin "backup_admin"

# Import database service account
terraform import windows_localuser.db_service "svc_sqlserver"

# Import IIS application pool identity
terraform import windows_localuser.iis_apppool "iis_apppool_user"