# Import a firewall profile by name (one of Domain, Private, Public).
# Profiles always exist, so import only adopts the live settings into state;
# nothing is created. The observed values become the snapshot for a later
# restore_on_destroy, and disabled_interface_aliases starts unmanaged (null).
terraform import windows_firewall_profile.private 'Private'
