# Import an existing domain membership by the domain DNS name (lower-case).
# The host is verified to actually be joined to that domain. The join
# credential is never in state for password_wo, so set join_credential in
# configuration (and apply) after importing.
terraform import windows_domain_membership.this corp.example.com
