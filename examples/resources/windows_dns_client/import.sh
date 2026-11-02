# Import the DNS client settings of an existing interface by alias.
# Both families become managed (automatic families import as []).
terraform import windows_dns_client.secondary "Ethernet 2"
