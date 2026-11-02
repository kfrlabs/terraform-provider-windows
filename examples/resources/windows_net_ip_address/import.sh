# Import an existing static IP address by <interface_alias>|<ip_address>.
# Only addresses with prefix origin Manual are importable.
terraform import windows_net_ip_address.storage "Ethernet 2|192.0.2.10"
