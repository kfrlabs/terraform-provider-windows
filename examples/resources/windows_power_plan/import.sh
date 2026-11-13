# Import the live active power plan of the target Windows host.
# The active plan is a singleton, so any non-empty import ID is accepted and
# ignored: the live plan is adopted and becomes the snapshot for a later
# restore_on_destroy.
terraform import windows_power_plan.this current
