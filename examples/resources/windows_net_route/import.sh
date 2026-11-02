# Import an existing persistent route by <interface_alias>|<destination_prefix>|<next_hop>.
# Only routes with protocol NetMgmt are importable; automatic routes (Local
# on-link routes derived from addresses, Dhcp gateways) are refused.
terraform import windows_net_route.backup "Ethernet 2|198.51.100.0/24|192.0.2.1"
