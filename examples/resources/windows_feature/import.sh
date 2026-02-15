# Import an existing Web-Server installation
terraform import windows_feature.web_server "Web-Server"

# Import Active Directory Domain Services
terraform import windows_feature.ad_domain_services "AD-Domain-Services"

# Import DNS Server
terraform import windows_feature.dns_server "DNS"

# Import DHCP Server
terraform import windows_feature.dhcp_server "DHCP"

# Import Hyper-V
terraform import windows_feature.hyperv "Hyper-V"

# Import File Server Resource Manager
terraform import windows_feature.fsrm "FS-Resource-Manager"

# Import Remote Desktop Services
terraform import windows_feature.rds "RDS-RD-Server"