# Import basic groups
terraform import windows_localgroup.developers "Developers"
terraform import windows_localgroup.admins "CustomAdmins"

# Import built-in Windows groups
terraform import windows_localgroup.existing_users "Users"
terraform import windows_localgroup.hyperv_admins "Hyper-V Administrators"
terraform import windows_localgroup.log_readers "Event Log Readers"
terraform import windows_localgroup.perf_users "Performance Monitor Users"
terraform import windows_localgroup.dcom_users "Distributed COM Users"

# Import built-in administrator groups
terraform import windows_localgroup.administrators "Administrators"
terraform import windows_localgroup.backup_operators "Backup Operators"
terraform import windows_localgroup.power_users "Power Users"
terraform import windows_localgroup.remote_desktop "Remote Desktop Users"

# Import application-specific groups
terraform import windows_localgroup.webapp_users "WebApp_Users"
terraform import windows_localgroup.webapp_admins "WebApp_Admins"

# Import database groups
terraform import windows_localgroup.db_readers "DB_Readers"
terraform import windows_localgroup.db_writers "DB_Writers"

# Import service groups
terraform import windows_localgroup.service_operators "ServiceOperators"
terraform import windows_localgroup.app_services "AppServices"

# Import file server groups
terraform import windows_localgroup.fileserver_users "FileServer_Users"
terraform import windows_localgroup.fileserver_powerusers "FileServer_PowerUsers"

# Import security groups
terraform import windows_localgroup.auditors "SecurityAuditors"
terraform import windows_localgroup.level1_access "Security_Level1"
terraform import windows_localgroup.level2_access "Security_Level2"
terraform import windows_localgroup.level3_access "Security_Level3"

# Import management groups
terraform import windows_localgroup.network_admins "NetworkAdmins"
terraform import windows_localgroup.print_ops "PrintOperators"
terraform import windows_localgroup.helpdesk "HelpDesk"
terraform import windows_localgroup.cert_admins "CertificateAdmins"
terraform import windows_localgroup.iis_admins "IIS_Admins"

# Import multiple groups using for_each
terraform import 'windows_localgroup.environment_groups["Dev_Team"]' "Dev_Team"
terraform import 'windows_localgroup.environment_groups["QA_Team"]' "QA_Team"
terraform import 'windows_localgroup.environment_groups["Ops_Team"]' "Ops_Team"

# Import other built-in groups
terraform import windows_localgroup.guests "Guests"
terraform import windows_localgroup.replicator "Replicator"
terraform import windows_localgroup.network_config_ops "Network Configuration Operators"
terraform import windows_localgroup.cryptographic_ops "Cryptographic Operators"