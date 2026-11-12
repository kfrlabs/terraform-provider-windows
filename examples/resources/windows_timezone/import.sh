# Import the live system time zone of the target Windows host.
# The zone is a singleton, so any non-empty import ID is accepted and ignored:
# the live zone is adopted and becomes the snapshot for a later
# restore_on_destroy.
terraform import windows_timezone.this current
